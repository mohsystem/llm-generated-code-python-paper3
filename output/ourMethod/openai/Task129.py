import os
import re
import stat
import tempfile
from typing import Tuple

MAX_SIZE_BYTES = 1024 * 1024  # 1 MiB
SAFE_FILE_NAME = re.compile(r'^[A-Za-z0-9._-]{1,255}$')

def is_valid_file_name(file_name: str) -> bool:
    if not isinstance(file_name, str):
        return False
    if len(file_name) < 1 or len(file_name) > 255:
        return False
    return SAFE_FILE_NAME.fullmatch(file_name) is not None

def retrieve_file_content(base_dir: str, file_name: str) -> Tuple[bool, str]:
    try:
        if not is_valid_file_name(file_name):
            return False, "ERROR: Invalid file name format."

        if not isinstance(base_dir, str) or not base_dir:
            return False, "ERROR: Invalid base directory."

        base_dir_abs = os.path.abspath(base_dir)
        if not os.path.isdir(base_dir_abs):
            return False, "ERROR: Base directory does not exist."

        # Prevent path traversal by restricting to file names only
        path = os.path.join(base_dir_abs, file_name)

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            return False, "ERROR: File not found."
        except OSError as e:
            return False, f"ERROR: {e.strerror}."

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return False, "ERROR: Not a regular file."
            if st.st_size < 0 or st.st_size > MAX_SIZE_BYTES:
                return False, "ERROR: File too large."

            remaining = min(st.st_size, MAX_SIZE_BYTES)
            chunks = []
            while remaining > 0:
                chunk = os.read(fd, int(min(65536, remaining)))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = data.decode("latin-1", errors="replace")
            return True, f"OK: {text}"
        finally:
            try:
                os.close(fd)
            except Exception:
                pass
    except Exception as e:
        return False, f"ERROR: {str(e)}"

def safe_write_atomic(base_dir: str, file_name: str, content: str) -> None:
    if not is_valid_file_name(file_name):
        raise ValueError("Invalid file name.")
    os.makedirs(base_dir, exist_ok=True)
    target = os.path.join(base_dir, file_name)
    with tempfile.NamedTemporaryFile(dir=base_dir, prefix=".tmp-", suffix=".part", delete=False) as tf:
        temp_name = tf.name
        data = content.encode("utf-8")
        if len(data) > MAX_SIZE_BYTES:
            raise ValueError("Content too large.")
        tf.write(data)
        tf.flush()
        os.fsync(tf.fileno())
    try:
        os.replace(temp_name, target)  # atomic on POSIX and Windows
    except Exception:
        try:
            os.remove(temp_name)
        except Exception:
            pass
        raise

def main() -> None:
    base_dir = "server_files"
    # Setup test files
    safe_write_atomic(base_dir, "sample1.txt", "Hello from sample1.\nThis is a test file.")
    safe_write_atomic(base_dir, "safe-2.log", "Log line 1\nLog line 2\n")

    # 5 test cases
    test_files = [
        "sample1.txt",     # valid
        "../secret.txt",   # invalid traversal attempt
        "/etc/passwd",     # invalid absolute path
        "missing.txt",     # non-existent
        "safe-2.log",      # valid
    ]

    for tf in test_files:
        ok, result = retrieve_file_content(base_dir, tf)
        print(f"Request: '{tf}' => {result}")

if __name__ == "__main__":
    main()