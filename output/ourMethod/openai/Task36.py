import os
import stat
import tempfile
from typing import List

def _is_safe_relative_path(user_path: str) -> bool:
    if user_path is None or len(user_path) == 0 or len(user_path) > 4096:
        return False
    if "\x00" in user_path:
        return False
    # Disallow absolute and drive-letter paths
    if os.path.isabs(user_path):
        return False
    drive, _ = os.path.splitdrive(user_path)
    if drive:
        return False
    # Disallow traversal and empty segments
    parts = []
    for sep_part in user_path.replace("\\", "/").split("/"):
        if sep_part in ("", ".", ".."):
            return False
        parts.append(sep_part)
    return True

def safe_read_file(base_dir: str, user_path: str) -> str:
    try:
        if base_dir is None or len(base_dir) == 0 or len(base_dir) > 4096:
            return "ERROR: Invalid base directory"
        if not _is_safe_relative_path(user_path):
            return "ERROR: Invalid file path"

        base_abs = os.path.abspath(base_dir)
        if not os.path.isdir(base_abs):
            return "ERROR: Base directory does not exist or is not a directory"

        candidate = os.path.normpath(os.path.join(base_abs, user_path))
        # Ensure candidate is inside base_abs
        try:
            common = os.path.commonpath([base_abs, candidate])
        except ValueError:
            return "ERROR: Invalid path resolution"
        if common != base_abs:
            return "ERROR: Path escapes base directory"

        # Reject if any existing component is a symlink
        walk = base_abs
        for part in user_path.replace("\\", "/").split("/"):
            walk = os.path.join(walk, part)
            if os.path.lexists(walk) and os.path.islink(walk):
                return "ERROR: Symlinks are not allowed"

        if not os.path.exists(candidate):
            return "ERROR: File does not exist"
        if not os.path.isfile(candidate):
            return "ERROR: Not a regular file"

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = None
        try:
            fd = os.open(candidate, flags)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return "ERROR: Not a regular file"
            max_size = 5 * 1024 * 1024  # 5 MB
            if st.st_size > max_size:
                return "ERROR: File too large"
            chunks: List[bytes] = []
            while True:
                b = os.read(fd, 8192)
                if not b:
                    break
                chunks.append(b)
            data = b"".join(chunks)
            return data.decode("utf-8", errors="strict")
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass
    except Exception as e:
        return f"ERROR: {e}"

def _setup_test_env() -> str:
    base = tempfile.mkdtemp(prefix="sandbox36_py_")
    with open(os.path.join(base, "a.txt"), "w", encoding="utf-8") as f:
        f.write("Hello from Python A\n")
    os.makedirs(os.path.join(base, "sub"), exist_ok=True)
    with open(os.path.join(base, "sub", "b.txt"), "w", encoding="utf-8") as f:
        f.write("Hello from Python B\n")
    os.makedirs(os.path.join(base, "dir"), exist_ok=True)
    try:
        os.symlink("a.txt", os.path.join(base, "link_to_a.txt"))
    except Exception:
        pass
    return base

def main() -> None:
    base = _setup_test_env()
    tests = [
        "a.txt",
        "sub/b.txt",
        "../x.txt",
        "dir",
        "link_to_a.txt",
    ]
    for t in tests:
        out = safe_read_file(base, t)
        print(out)

if __name__ == "__main__":
    main()