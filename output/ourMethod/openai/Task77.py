import os
import re
import ssl
import sys
import errno
import tempfile
from ftplib import FTP_TLS
from typing import Tuple, Optional


def _build_ssl_context() -> ssl.SSLContext:
    """
    Build a secure SSL context enforcing TLS 1.2+, certificate validation,
    and strict hostname verification.
    """
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Enforce TLS 1.2 or higher
    if hasattr(ssl, "TLSVersion"):  # Python 3.10+
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        ctx.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    return ctx


def _is_valid_hostname(hostname: str) -> bool:
    """
    Validate hostname according to RFC-style rules for hostnames and IPv4/IPv6 literals.
    """
    if not hostname or len(hostname) > 253:
        return False

    # Allow IPv6 literals in brackets, e.g., [2001:db8::1]
    if hostname.startswith('[') and hostname.endswith(']') and len(hostname) <= 255:
        inner = hostname[1:-1]
        # Very loose IPv6 check to avoid external dependencies
        return bool(re.fullmatch(r"[0-9A-Fa-f:]+", inner))

    # IPv4 address
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname):
        try:
            parts = [int(p) for p in hostname.split(".")]
            return all(0 <= p <= 255 for p in parts)
        except ValueError:
            return False

    # Hostname labels
    label = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    hostname_re = re.compile(rf"^{label}(?:\.{label})*$")
    return bool(hostname_re.fullmatch(hostname))


def _validate_inputs(host: str, username: str, password: str, remote_path: str, port: int) -> None:
    """
    Validate all external inputs. Raise ValueError on invalid data.
    """
    if not isinstance(host, str) or not _is_valid_hostname(host.strip()):
        raise ValueError("Invalid hostname provided.")

    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("Invalid port. Must be in range 1..65535.")

    if not isinstance(username, str) or not (1 <= len(username) <= 128):
        raise ValueError("Invalid username length.")

    if not isinstance(password, str) or not (1 <= len(password) <= 256):
        raise ValueError("Invalid password length.")

    if not isinstance(remote_path, str) or not (1 <= len(remote_path) <= 4096):
        raise ValueError("Invalid remote path length.")

    # Disallow NUL bytes in any string inputs
    for field in (host, username, password, remote_path):
        if "\x00" in field:
            raise ValueError("NUL byte is not allowed in inputs.")


def _sanitize_local_filename(remote_path: str, base_dir: str) -> str:
    """
    Derive a safe local filename from a remote path.
    Ensures the resulting path is inside base_dir and not a directory/symlink.
    """
    # Extract basename and remove dangerous characters
    raw_name = os.path.basename(remote_path)
    if not raw_name or raw_name in (".", ".."):
        raw_name = "downloaded_file"

    # Replace control and path-separator characters
    safe = re.sub(r"[\\/\x00-\x1F\x7F]", "_", raw_name)
    # Limit length to avoid filesystem issues
    safe = safe[:255] if len(safe) > 255 else safe
    if not safe:
        safe = "downloaded_file"

    # Normalize and ensure within base_dir
    base_dir = os.path.abspath(base_dir)
    candidate = os.path.normpath(os.path.join(base_dir, safe))
    if os.path.commonpath([base_dir, candidate]) != base_dir:
        raise ValueError("Resolved output path escapes the base directory.")

    return candidate


def _prepare_output_file(final_path: str) -> Tuple[int, str]:
    """
    Prepare a secure temporary file in the same directory as final_path.
    Returns (fd, temp_path).
    Ensures permissions are set to 0o600.
    """
    directory = os.path.dirname(os.path.abspath(final_path))
    filename = os.path.basename(final_path)
    # Create a temp file in the same directory; avoid symlinks by specifying dir directly
    fd, temp_path = tempfile.mkstemp(prefix=f".{filename}.", suffix=".tmp", dir=directory, text=False)
    try:
        os.fchmod(fd, 0o600)
    except AttributeError:
        # On platforms without fchmod, best-effort by chmod on path
        try:
            os.chmod(temp_path, 0o600)
        except Exception:
            pass
    return fd, temp_path


def _atomic_replace(src: str, dst: str) -> None:
    """
    Atomically replace dst with src. If dst exists, refuse to overwrite for safety.
    This helps mitigate symlink attacks and accidental overwrites.
    """
    # If destination exists, fail closed
    try:
        st = os.lstat(dst)
        # Destination exists; refuse to overwrite (could be a symlink)
        raise FileExistsError(errno.EEXIST, "Destination file already exists.", dst)
    except FileNotFoundError:
        # Does not exist; proceed
        pass

    # Atomic rename into place
    os.replace(src, dst)


def download_sensitive_file(
    host: str,
    username: str,
    password: str,
    remote_path: str,
    port: int = 21,
    timeout: float = 20.0,
) -> str:
    """
    Securely connect to an FTPS server (explicit TLS), authenticate, and download a file to CWD.

    Parameters:
        host: FTP server hostname or IP (FTPS explicit).
        username: Username for authentication.
        password: Password for authentication.
        remote_path: Remote file path to retrieve.
        port: Server port (default 21 for explicit FTPS).
        timeout: Socket timeout in seconds.

    Returns:
        The absolute path to the downloaded local file.

    Raises:
        ValueError for invalid inputs.
        RuntimeError for network/FTP errors.
    """
    _validate_inputs(host, username, password, remote_path, port)

    base_dir = os.getcwd()
    final_path = _sanitize_local_filename(remote_path, base_dir)

    ssl_ctx = _build_ssl_context()

    ftps: Optional[FTP_TLS] = None
    fd: Optional[int] = None
    temp_path: Optional[str] = None

    try:
        # Connect using explicit FTPS
        ftps = FTP_TLS(context=ssl_ctx, timeout=timeout)
        ftps.connect(host=host, port=port, timeout=timeout)
        # Upgrade to TLS explicitly before login (AUTH TLS)
        ftps.auth()
        # Perform login (do not log or print credentials)
        ftps.login(user=username, passwd=password)
        # Protect data connection (PROT P)
        ftps.prot_p()

        # Prepare temp output file
        fd, temp_path = _prepare_output_file(final_path)

        # Use a file object from fd
        with os.fdopen(fd, "wb", buffering=1024 * 1024) as fobj:
            fd = None  # fd now owned by fobj
            def writer(block: bytes) -> None:
                # Ensure we only write bytes and keep within boundaries
                if not isinstance(block, (bytes, bytearray, memoryview)):
                    raise RuntimeError("Invalid data block received from FTP transfer.")
                fobj.write(block)

            # Retrieve the file in binary mode
            ftps.retrbinary(f"RETR {remote_path}", writer, blocksize=8192)

            # Flush and fsync to disk
            fobj.flush()
            os.fsync(fobj.fileno())

        # Atomically move temp file into final destination (refuse overwrite)
        if temp_path is None:
            raise RuntimeError("Internal error: temp file path is None.")
        _atomic_replace(temp_path, final_path)
        temp_path = None  # moved

        return os.path.abspath(final_path)

    except FileExistsError as ex:
        raise RuntimeError(f"Refusing to overwrite existing file: {ex.filename}") from ex
    except Exception as ex:
        raise RuntimeError(f"Download failed: {ex}") from ex
    finally:
        # Cleanup temp file on failure
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        if ftps is not None:
            try:
                # quit sends a polite 'QUIT' command; if it fails, close anyway
                ftps.quit()
            except Exception:
                try:
                    ftps.close()
                except Exception:
                    pass


def _print_usage() -> None:
    print(
        "Usage:\n"
        "  python script.py <host> <username> <password> <remote_path> [port]\n"
        "Example:\n"
        "  python script.py ftp.example.com alice S3cr3t! /secure/secret.txt 21",
        file=sys.stderr,
    )


def _run_tests() -> None:
    # 5 test cases (no network required except last one which is expected to fail fast)
    tests_passed = 0

    # 1) Invalid hostname
    try:
        _validate_inputs("bad host*", "user", "pass", "/file.txt", 21)
        print("Test 1 failed: invalid hostname not detected")
    except ValueError:
        print("Test 1 passed: invalid hostname detected")
        tests_passed += 1

    # 2) Invalid port
    try:
        _validate_inputs("example.com", "user", "pass", "/file.txt", 70000)
        print("Test 2 failed: invalid port not detected")
    except ValueError:
        print("Test 2 passed: invalid port detected")
        tests_passed += 1

    # 3) Invalid username length
    try:
        _validate_inputs("example.com", "", "pass", "/file.txt", 21)
        print("Test 3 failed: empty username not detected")
    except ValueError:
        print("Test 3 passed: empty username detected")
        tests_passed += 1

    # 4) Sanitize filename from remote path traversal
    try:
        safe_path = _sanitize_local_filename("../../etc/passwd", os.getcwd())
        if os.path.dirname(safe_path) == os.getcwd() and os.path.basename(safe_path) in ("passwd", "downloaded_file", "passwd"[0:255]):
            print("Test 4 passed: sanitized filename confined to CWD")
            tests_passed += 1
        else:
            print("Test 4 failed: filename not properly sanitized")
    except Exception:
        print("Test 4 failed: exception during sanitization")

    # 5) Attempt download with unreachable host (expected to fail fast)
    try:
        # Very small timeout to fail quickly without hanging
        download_sensitive_file("nonexistent.invalid", "user", "password", "/file.txt", 21, timeout=1.0)
        print("Test 5 failed: expected failure on unreachable host")
    except RuntimeError:
        print("Test 5 passed: failure on unreachable host handled safely")
        tests_passed += 1

    print(f"Tests passed: {tests_passed}/5")


def main(argv: list) -> int:
    if len(argv) == 1:
        # No arguments: run tests
        _run_tests()
        return 0

    if len(argv) < 5 or len(argv) > 6:
        _print_usage()
        return 2

    host = argv[1].strip()
    username = argv[2]
    password = argv[3]
    remote_path = argv[4]
    port = 21
    if len(argv) == 6:
        try:
            port = int(argv[5])
        except ValueError:
            print("Port must be an integer.", file=sys.stderr)
            return 2

    try:
        local_path = download_sensitive_file(host, username, password, remote_path, port=port)
        print(f"Downloaded file saved to: {local_path}")
        return 0
    except Exception as ex:
        print(f"Error: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))