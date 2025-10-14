import os
import sys
import ssl
import shutil
import stat
import platform
import urllib.parse
import urllib.request
import tempfile
import subprocess
from typing import Tuple


def download_and_execute(url: str, base_dir: str, perform: bool) -> str:
    # Validate inputs
    if not isinstance(url, str) or not url.strip():
        return "ERROR: URL is empty."
    if len(url) > 2048:
        return "ERROR: URL too long."
    if not isinstance(base_dir, str) or not base_dir.strip():
        return "ERROR: Base directory is empty."

    try:
        parsed = urllib.parse.urlparse(url.strip())
    except Exception:
        return "ERROR: Invalid URL syntax."

    if parsed.scheme.lower() != "https":
        return "ERROR: Only HTTPS URLs are allowed."
    if not parsed.hostname or len(parsed.hostname) > 253:
        return "ERROR: URL must include a valid host."

    # Derive a safe filename
    name = os.path.basename(parsed.path) or "download.exe"
    # Sanitize
    safe = []
    for ch in name:
        if ch.isalnum() or ch in "._-":
            safe.append(ch)
        else:
            safe.append("_")
    name = "".join(safe)
    if not name.lower().endswith(".exe"):
        name += ".exe"
    if len(name) > 128:
        name = name[-128:]

    # Prepare base directory
    base_dir = os.path.abspath(os.path.normpath(base_dir))
    try:
        if os.path.exists(base_dir):
            if os.path.islink(base_dir):
                return "ERROR: Base directory must not be a symlink."
            if not os.path.isdir(base_dir):
                return "ERROR: Base path exists but is not a directory."
        else:
            os.makedirs(base_dir, exist_ok=True)
    except Exception as e:
        return f"ERROR: Unable to prepare base directory: {e}"

    dest_path = os.path.abspath(os.path.normpath(os.path.join(base_dir, name)))
    # Prevent path traversal
    if not dest_path.startswith(base_dir + os.sep) and dest_path != base_dir:
        return "ERROR: Resolved destination escapes base directory."

    if not perform:
        return f"DRY-RUN: Would download {url} to {dest_path} and execute it on Windows."

    # TLS context with verification (revocation checking not enabled by default in Python stdlib)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        # OCSP stapling/revocation checks are not universally available via stdlib; best-effort only.
    except Exception as e:
        return f"ERROR: SSL context creation failed: {e}"

    # Download to a secure temporary file in base_dir
    tmp_fd = None
    tmp_path = None
    max_bytes = 100 * 1024 * 1024  # 100 MB
    total = 0

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Task86Downloader/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            if resp.status < 200 or resp.status >= 300:
                return f"ERROR: HTTP status {resp.status} received."

            tmp_fd, tmp_path = tempfile.mkstemp(prefix="dl_", suffix=".tmp", dir=base_dir)
            with os.fdopen(tmp_fd, "wb", buffering=0) as f:
                # Attempt to lock file (best-effort)
                try:
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except Exception:
                    pass

                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        return "ERROR: Download exceeds maximum allowed size."
                    f.write(chunk)
                    f.flush()
                    os.fsync(f.fileno())

            # Restrictive permissions
            try:
                os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            except Exception:
                pass

            # Atomic move into place
            os.replace(tmp_path, dest_path)

            # Final validation
            if os.path.islink(dest_path) or not os.path.isfile(dest_path):
                return "ERROR: Final file is not a regular file."

    except Exception as e:
        try:
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except Exception:
                    pass
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return f"ERROR: Download failed: {e}"

    # Execute only on Windows
    if platform.system().lower() != "windows":
        return f"OK: Downloaded to {dest_path} but not executed (non-Windows OS)."

    try:
        completed = subprocess.run([dest_path], cwd=base_dir, timeout=15)
        return f"OK: Executed {dest_path} with exit code {completed.returncode}."
    except subprocess.TimeoutExpired:
        return f"OK: Executed {dest_path} but terminated due to timeout."
    except Exception as e:
        return f"ERROR: Execution failed: {e}"


def main() -> None:
    base = tempfile.gettempdir()
    tests = [
        "https://example.com/vendor/product.exe",
        "http://example.com/insecure.exe",
        "https://example.com/path/../../../evil.exe",
        "https://very-long-host-name-that-is-probably-invalid.example.com/" + ("a" * 200) + ".exe",
        ""
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {download_and_execute(t, base, perform=False)}")


if __name__ == "__main__":
    main()