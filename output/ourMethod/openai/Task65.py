import os
import re
import sys
import stat
from typing import Optional

MAX_FILE_SIZE = 2_000_000  # 2 MB
FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,255}$")

def read_file_secure(base_dir: str, user_filename: str) -> str:
    if base_dir is None or user_filename is None:
        return "ERROR: Base directory or filename is None."

    if not isinstance(user_filename, str) or not FILENAME_PATTERN.fullmatch(user_filename):
        return "ERROR: Invalid filename format. Allowed: letters, digits, . _ - (1-255 chars)"

    try:
        base_abs = os.path.abspath(base_dir)
        try:
            st_base = os.lstat(base_abs)
        except FileNotFoundError:
            return "ERROR: Base directory does not exist."
        except OSError as e:
            return f"ERROR: Cannot access base directory: {e}"

        if stat.S_ISLNK(st_base.st_mode):
            return "ERROR: Base directory must not be a symbolic link."
        if not stat.S_ISDIR(st_base.st_mode):
            return "ERROR: Base path is not a directory."

        file_path = os.path.normpath(os.path.join(base_abs, user_filename))
        # Ensure the file is directly under base (no separators in filename and parent equals base)
        if os.path.dirname(file_path) != base_abs:
            return "ERROR: Resolved path is outside the base directory."

        try:
            st = os.lstat(file_path)
        except FileNotFoundError:
            return "ERROR: File does not exist."
        except OSError as e:
            return f"ERROR: Unable to access file: {e}"

        if stat.S_ISLNK(st.st_mode):
            return "ERROR: Refusing to read a symbolic link."
        if not stat.S_ISREG(st.st_mode):
            return "ERROR: Path is not a regular file."
        if st.st_size > MAX_FILE_SIZE:
            return "ERROR: File too large (limit 2 MB)."

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = None
        try:
            fd = os.open(file_path, flags)
        except OSError as e:
            return f"ERROR: Unable to open file: {e}"

        try:
            st2 = os.fstat(fd)
            if not stat.S_ISREG(st2.st_mode):
                return "ERROR: Opened path is not a regular file."
            if st2.st_size > MAX_FILE_SIZE:
                return "ERROR: File too large (limit 2 MB)."

            remaining = st2.st_size
            chunks = []
            to_read = 8192
            total = 0
            while True:
                data = os.read(fd, to_read)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if total > MAX_FILE_SIZE:
                    return "ERROR: File too large while reading (limit 2 MB)."
            content = b"".join(chunks)
            return content.decode("utf-8", errors="replace")
        except OSError as e:
            return f"ERROR: Error reading file: {e}"
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            except OSError:
                pass
    except Exception as e:
        return f"ERROR: Unexpected error: {e}"

def _run_tests():
    base = "."
    tests = [
        "README.md",               # May or may not exist
        "no_such_file.txt",       # Non-existent
        "bad/../path",            # Invalid format (contains '/')
        "a" * 260,                # Too long
        ".",                      # Directory, not regular file
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} ({t}):")
        print(read_file_secure(base, t))
        print("-----")

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        print(read_file_secure(sys.argv[1], sys.argv[2]))
    else:
        _run_tests()