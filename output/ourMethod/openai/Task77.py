import os
import re
import ssl
from ftplib import FTP_TLS
from pathlib import Path
from typing import Optional

def download_ftp_file(host: str, username: str, password: str, remote_path: str) -> str:
    _validate_inputs(host, username, password, remote_path)
    local_name = _sanitize_filename(remote_path)
    if not local_name:
        local_name = "downloaded.bin"

    # Prepare SSL context with strict verification
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    temp_path = None
    ftp: Optional[FTP_TLS] = None
    try:
        ftp = FTP_TLS(context=context, timeout=30)
        ftp.connect(host=host, port=21, timeout=15)
        ftp.auth()  # Explicit TLS
        ftp.login(user=username, passwd=password)
        ftp.prot_p()  # Secure data channel

        # Create temp file in current directory
        tmp = Path(".") / (".dl_part_" + next(_temp_suffix()))
        temp_path = str(tmp)

        # Open file, set restrictive permissions
        with os.fdopen(os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb", buffering=0) as f:
            # Binary transfer
            def writer(data: bytes) -> None:
                f.write(data)

            # Use RETR with exact path; ftplib handles quoting minimally
            ftp.retrbinary("RETR " + remote_path, writer, blocksize=8192)

            f.flush()
            os.fsync(f.fileno())

        final_path = str(Path(".") / local_name)
        os.replace(temp_path, final_path)
        temp_path = None
        return str(Path(final_path).resolve())
    except Exception as e:
        raise RuntimeError("Download failed") from e
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
        if temp_path:
            try:
                os.remove(temp_path)
            except Exception:
                pass

def _validate_inputs(host: str, username: str, password: str, remote_path: str) -> None:
    if not isinstance(host, str) or not (1 <= len(host) <= 255) or not re.fullmatch(r"[A-Za-z0-9._-]+", host):
        raise ValueError("Invalid host")
    if not isinstance(username, str) or not (1 <= len(username) <= 128):
        raise ValueError("Invalid username")
    if not isinstance(password, str) or not (1 <= len(password) <= 256):
        raise ValueError("Invalid password")
    if not isinstance(remote_path, str) or not (1 <= len(remote_path) <= 1024):
        raise ValueError("Invalid remote path")
    if remote_path.endswith("/"):
        raise ValueError("Remote path must be a file, not a directory")

def _sanitize_filename(remote_path: str) -> str:
    base = remote_path.replace("\\", "/").split("/")[-1]
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if base in ("", ".", ".."):
        return "downloaded.bin"
    if len(base) > 255:
        base = base[:255]
    return base

def _temp_suffix():
    # Simple unique suffix generator
    counter = 0
    while True:
        counter += 1
        yield f"{os.getpid()}_{counter}"

def _run_tests():
    tests = [
        ("invalid.example", "user", "pass", "/readme.txt"),
        ("example.com", "anonymous", "guest@example.com", "/pub/example.dat"),
        ("localhost", "ftpuser", "p@ssw0rd!", "folder/file.txt"),
        ("ftp.example.org", "user_name", "secret", "/path/with space/file name.bin"),
        ("192.0.2.10", "u", "p", "/sensitive/secret.bin"),
    ]
    for i, (h, u, p, rp) in enumerate(tests, 1):
        try:
            path = download_ftp_file(h, u, p, rp)
            print(f"Test {i} downloaded to: {path}")
        except Exception as e:
            print(f"Test {i} failed: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 5:
        try:
            result = download_ftp_file(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
            print(f"Downloaded to: {result}")
        except Exception as e:
            print(f"Operation failed: {e}")
            raise SystemExit(1)
    else:
        print("Usage: python3 task77.py <host> <username> <password> <remotePath>")
        _run_tests()