import os
import re
import stat
import errno
import secrets

MAX_SIZE = 10 * 1024 * 1024
SAFE_NAME = re.compile(r'^[A-Za-z0-9._-]{1,255}$')

def upload_file(filename: str, data: bytes) -> str:
    if not isinstance(filename, str) or not isinstance(data, (bytes, bytearray)):
        raise ValueError("Invalid input")
    if not SAFE_NAME.fullmatch(filename):
        raise ValueError("Invalid filename")
    if len(data) > MAX_SIZE:
        raise ValueError("File too large")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    basefd = updfd = tmpfd = None
    tmpname = None

    try:
        basefd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        # Ensure uploads directory exists and is not a symlink
        try:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            updfd = os.openat(basefd, "uploads", flags)
        except FileNotFoundError:
            os.mkdir("uploads", mode=0o700, dir_fd=basefd)
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            updfd = os.openat(basefd, "uploads", flags)

        # Create a unique temporary file inside uploads
        tmpname = f".tmp-{os.getpid()}-{secrets.token_hex(8)}"
        oflags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                  getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        tmpfd = os.openat(updfd, tmpname, oflags, 0o600)

        # Validate that the opened handle is a regular file
        st = os.fstat(tmpfd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("Not a regular file")

        # Write data safely
        remaining = memoryview(data)
        while remaining:
            n = os.write(tmpfd, remaining)
            if n <= 0:
                raise OSError("Write failed")
            remaining = remaining[n:]

        os.fsync(tmpfd)

        # Atomically link into final destination name (no overwrite)
        # Use hard link to fail if destination exists; do not follow symlinks
        os.link(tmpname, filename, src_dir_fd=updfd, dst_dir_fd=updfd, follow_symlinks=False)

        # Remove temp name
        os.unlink(tmpname, dir_fd=updfd)

        # Optionally fsync directory to ensure durablity of metadata
        try:
            os.fsync(updfd)
        except Exception:
            pass

        return os.path.join(base_dir, "uploads", filename)

    except OSError as e:
        raise ValueError(f"Upload failed: {e.strerror}") from e
    finally:
        if tmpfd is not None:
            try: os.close(tmpfd)
            except Exception: pass
        if updfd is not None:
            try: os.close(updfd)
            except Exception: pass
        if basefd is not None:
            try: os.close(basefd)
            except Exception: pass

def _run_test(name, data):
    try:
        path = upload_file(name, data)
        print(f"OK: {name} -> {path}")
    except Exception as e:
        print(f"ERR: {name} -> {e}")

if __name__ == "__main__":
    _run_test("a.txt", b"hello")                       # success
    _run_test("b.png", bytes([1, 2, 3]))               # success
    _run_test("../bad.txt", b"oops")                   # traversal -> error
    _run_test("bad/inner.txt", b"oops")                # separator -> error
    _run_test("big.bin", b"\x00" * (MAX_SIZE + 1))     # too large -> error