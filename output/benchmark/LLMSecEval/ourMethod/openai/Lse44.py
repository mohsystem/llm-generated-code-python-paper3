import os
import re
import stat
import sys
import hashlib

MAX_SIZE = 4 * 1024 * 1024  # 4 MiB
BASE_DIR = "/safe"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")

def read_safe_file(name: str) -> bytes:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise OSError("invalid input")

    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("platform not supported")

    dirfd = -1
    fd = -1
    try:
        dirfd = os.open(BASE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dirfd)
        st = os.fstat(fd)

        if not stat.S_ISREG(st.st_mode):
            raise OSError("not regular file")

        if st.st_size < 0 or st.st_size > MAX_SIZE:
            raise OSError("file too large")

        remaining = st.st_size
        chunks = []
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != st.st_size:
            # Best-effort read; if file changed size, ensure limit
            if len(data) > MAX_SIZE:
                raise OSError("file too large")
        return data
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except Exception:
                pass
        if dirfd != -1:
            try:
                os.close(dirfd)
            except Exception:
                pass

def _sha1_hex(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()

def main():
    tests = [
        "example.txt",
        "does_not_exist.txt",
        "../passwd",
        "valid-file_123",
        "bad\\name",
    ]
    for t in tests:
        try:
            data = read_safe_file(t)
            print(f"OK {t} size={len(data)} sha1={_sha1_hex(data)}")
        except Exception:
            print(f"ERR {t}")

if __name__ == "__main__":
    main()