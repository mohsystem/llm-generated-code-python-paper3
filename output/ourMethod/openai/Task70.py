import os
import sys
import stat
import tempfile
from typing import Optional

DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10MB

def _is_symlink(path: str) -> bool:
    try:
        st = os.lstat(path)
        return stat.S_ISLNK(st.st_mode)
    except FileNotFoundError:
        return False

def _validate_base_dir(base_dir: str) -> Optional[str]:
    if not base_dir or len(base_dir) > 4096:
        return "Invalid base directory."
    try:
        st = os.lstat(base_dir)
        if not stat.S_ISDIR(st.st_mode):
            return "Base path is not a directory."
        if stat.S_ISLNK(st.st_mode):
            return "Base directory must not be a symbolic link."
    except FileNotFoundError:
        return "Base directory does not exist."
    except Exception as e:
        return f"Base directory error: {e}"
    return None

def read_file_secure(base_dir: str, requested_path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    try:
        err = _validate_base_dir(base_dir)
        if err:
            return f"ERROR: {err}"
        if not requested_path or len(requested_path) > 4096:
            return "ERROR: Invalid requested path."
        if os.path.isabs(requested_path):
            return "ERROR: Absolute paths are not allowed."

        base_abs = os.path.abspath(base_dir)
        # Normalize candidate path lexically
        candidate = os.path.normpath(os.path.join(base_abs, requested_path))

        # Ensure within base directory
        try:
            common = os.path.commonpath([base_abs, candidate])
        except ValueError:
            return "ERROR: Path error."
        if common != base_abs:
            return "ERROR: Path traversal detected."

        if not os.path.exists(candidate):
            return "ERROR: File does not exist."

        # Ensure no symlinks along the path
        rel = os.path.relpath(candidate, base_abs)
        parts = [] if rel == "." else rel.split(os.sep)
        cur = base_abs
        for p in parts:
            cur = os.path.join(cur, p)
            if _is_symlink(cur):
                return "ERROR: Symbolic links are not allowed."

        st = os.lstat(candidate)
        if not stat.S_ISREG(st.st_mode):
            return "ERROR: Not a regular file."

        if st.st_size > max_bytes:
            return "ERROR: File too large."

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        # On Windows, O_NOFOLLOW may not be available; we already checked symlinks along the path.

        fd = os.open(candidate, flags)
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                return "ERROR: Not a regular file."
            if fst.st_size > max_bytes:
                return "ERROR: File too large."

            remaining = max_bytes
            chunks = []
            while True:
                to_read = 8192 if remaining > 8192 else remaining
                if to_read <= 0:
                    break
                data = os.read(fd, to_read)
                if not data:
                    break
                chunks.append(data)
                remaining -= len(data)
                if remaining < 0:
                    return "ERROR: File grew beyond allowed size during read."
            content = b"".join(chunks)
            return content.decode("utf-8", errors="replace")
        finally:
            os.close(fd)
    except Exception as e:
        return f"ERROR: {e}"

def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)

def main() -> None:
    if len(sys.argv) >= 3:
        base = sys.argv[1]
        req = sys.argv[2]
        print(read_file_secure(base, req, DEFAULT_MAX_BYTES))
        return

    # Self-tests (5 cases)
    with tempfile.TemporaryDirectory(prefix="secure_read_base_py_") as base_dir:
        file1 = os.path.join(base_dir, "file1.txt")
        sub = os.path.join(base_dir, "sub")
        os.makedirs(sub, exist_ok=True)
        file2 = os.path.join(sub, "note.txt")
        _write_text(file1, "Hello world from file1")
        _write_text(file2, "Nested content")

        print("---- Test 1: Read simple file ----")
        print(read_file_secure(base_dir, "file1.txt"))

        print("---- Test 2: Read nested file ----")
        print(read_file_secure(base_dir, "sub" + os.sep + "note.txt"))

        print("---- Test 3: Path traversal attempt ----")
        print(read_file_secure(base_dir, "../etc/passwd"))

        print("---- Test 4: Read directory (should fail) ----")
        print(read_file_secure(base_dir, "sub"))

        print("---- Test 5: Read symlink (should fail) ----")
        outside = os.path.join(base_dir, "outside.txt")
        _write_text(outside, "Outside content")
        link = os.path.join(base_dir, "link_to_outside")
        try:
            if os.path.exists(link):
                os.unlink(link)
            os.symlink("outside.txt", link)
            print(read_file_secure(base_dir, "link_to_outside"))
        except (NotImplementedError, OSError, RuntimeError) as e:
            print(f"SKIPPED: Symlink not supported or permission denied - {e}")

if __name__ == "__main__":
    main()