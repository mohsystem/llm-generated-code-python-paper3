import os
import stat
import tempfile
import secrets
from typing import Tuple

def _is_valid_filename(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if len(name) == 0 or len(name) > 255:
        return False
    if name in (".", ".."):
        return False
    if "/" in name or "\\" in name:
        return False
    for ch in name:
        if not (ch.isalnum() or ch in "._-"):
            return False
    return True

def generate_and_write(base_dir: str, filename: str) -> str:
    if not isinstance(base_dir, str) or not isinstance(filename, str):
        raise ValueError("Invalid arguments")

    base_dir = os.path.abspath(base_dir)

    # Validate base directory (must be directory and not a symlink)
    try:
        st = os.lstat(base_dir)
    except OSError:
        raise OSError("Invalid base directory")
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise OSError("Invalid base directory")

    # Validate filename
    if not _is_valid_filename(filename):
        raise OSError("Invalid filename")

    # Generate random floats and concatenate
    rng = secrets.SystemRandom()
    f1 = rng.random()
    f2 = rng.random()
    f3 = rng.random()
    content = f"{f1}{f2}{f3}"

    # Create a secure temporary file in base_dir
    dirfd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        suffix = secrets.token_hex(8)
        tmp_name = f"tmp-{os.getpid()}-{suffix}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.openat(dirfd, tmp_name, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(os.path.join(base_dir, tmp_name))
            except OSError:
                pass
            raise

        target_path = os.path.join(base_dir, filename)
        # Atomic replace to avoid partial writes (may overwrite existing)
        os.replace(os.path.join(base_dir, tmp_name), target_path)

        # Best-effort directory sync
        try:
            os.fsync(dirfd)
        except OSError:
            pass

    finally:
        try:
            os.close(dirfd)
        except OSError:
            pass

    return content

if __name__ == "__main__":
    base = tempfile.mkdtemp(prefix="safe-out-")
    print("Base dir:", base)
    print("case1 ->", generate_and_write(base, "case1.txt"))
    print("case2 ->", generate_and_write(base, "case2.txt"))
    print("case3 ->", generate_and_write(base, "case3.txt"))
    print("case4 ->", generate_and_write(base, "case4.txt"))
    print("case5 ->", generate_and_write(base, "case5.txt"))