import os
import stat
from typing import Optional

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MiB
BASE_DIR = "/safe"

def _is_valid_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if len(name) < 1 or len(name) > 255:
        return False
    if name in (".", ".."):
        return False
    for ch in name:
        if ch in ('/', '\\', '\x00'):
            return False
        if not (ch.isalnum() or ch in "._-"):
            return False
    return True

def read_from_safe(name: str) -> bytes:
    if not _is_valid_name(name):
        raise ValueError("invalid input")

    # Open the base directory first (anchor), then open relative to it with no symlink following.
    dirfd: Optional[int] = None
    fd: Optional[int] = None
    try:
        dirfd = os.open(BASE_DIR, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        # Open relative path securely; do not follow symlinks
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=dirfd, follow_symlinks=False)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not a file")
        if st.st_size > MAX_FILE_SIZE:
            raise OSError("too large")

        # Read with strict bound
        buf = bytearray()
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_FILE_SIZE:
                raise OSError("too large")
        return bytes(buf)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        if dirfd is not None:
            try:
                os.close(dirfd)
            except Exception:
                pass

if __name__ == "__main__":
    tests = [
        "example.txt",
        "nonexistent.txt",
        "../passwd",
        "symlink",
        "nested.txt",
    ]
    for t in tests:
        try:
            data = read_from_safe(t)
            preview = data[:64].decode("utf-8", "replace").replace("\n", "\\n")
            print(f"Read {t}: {len(data)} bytes; preview: {preview}")
        except Exception:
            print(f"Read {t}: error")