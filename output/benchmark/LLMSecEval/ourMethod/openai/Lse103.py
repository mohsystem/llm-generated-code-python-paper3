import os
import stat
import tempfile
import sys

MAX_NAME_LENGTH = 255
SIZE_LIMIT = 10 * 1024 * 1024  # 10 MiB

def _require_simple_filename(filename: str) -> None:
    if not isinstance(filename, str):
        raise OSError("invalid name")
    if not filename or len(filename) > MAX_NAME_LENGTH:
        raise OSError("invalid name")
    if filename in (".", ".."):
        raise OSError("invalid name")
    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise OSError("invalid name")

def _open_base_dir(base_dir: str) -> int:
    if not isinstance(base_dir, str) or not base_dir:
        raise OSError("invalid base dir")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    dfd = os.open(base_dir, flags)
    try:
        st = os.fstat(dfd)
        if not stat.S_ISDIR(st.st_mode):
            raise OSError("base not dir")
    except:
        os.close(dfd)
        raise
    return dfd

def _write_all(fd: int, data: bytes) -> int:
    if data is None:
        data = b""
    if not isinstance(data, (bytes, bytearray)):
        raise OSError("invalid data")
    if len(data) > SIZE_LIMIT:
        raise OSError("too large")
    total = 0
    view = memoryview(data)
    while total < len(data):
        n = os.write(fd, view[total:])
        if n <= 0:
            raise OSError("write error")
        total += n
    os.fsync(fd)
    return total

def secure_create_new_file(base_dir: str, filename: str, content: bytes) -> int:
    _require_simple_filename(filename)
    dfd = _open_base_dir(base_dir)
    fd = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.openat(dfd, filename, flags, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not regular")
        written = _write_all(fd, content)
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except:
                pass
        try:
            os.fsync(dfd)
        except:
            pass
        try:
            os.close(dfd)
        except:
            pass
    return written

def secure_truncate_and_write_file(base_dir: str, filename: str, content: bytes) -> int:
    _require_simple_filename(filename)
    dfd = _open_base_dir(base_dir)
    fd = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.openat(dfd, filename, flags, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not regular")
        written = _write_all(fd, content)
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except:
                pass
        try:
            os.fsync(dfd)
        except:
            pass
        try:
            os.close(dfd)
        except:
            pass
    return written

if __name__ == "__main__":
    base_dir = tempfile.mkdtemp(prefix="secure_open_demo_")
    try:
        # 1) Create new file (success)
        try:
            n1 = secure_create_new_file(base_dir, "a.txt", b"hello")
            print("Test1 create_new a.txt bytes=" + str(n1))
        except Exception:
            print("Test1 failure")

        # 2) Create same file again (should fail)
        try:
            secure_create_new_file(base_dir, "a.txt", b"x")
            print("Test2 unexpected success")
        except Exception:
            print("Test2 expected failure")

        # 3) Truncate and write existing file
        try:
            n3 = secure_truncate_and_write_file(base_dir, "a.txt", b"world")
            print("Test3 truncate a.txt bytes=" + str(n3))
        except Exception:
            print("Test3 failure")

        # 4) Create new different file
        try:
            n4 = secure_create_new_file(base_dir, "b.txt", b"data")
            print("Test4 create_new b.txt bytes=" + str(n4))
        except Exception:
            print("Test4 failure")

        # 5) Invalid path traversal attempt
        try:
            secure_create_new_file(base_dir, "../evil.txt", b"bad")
            print("Test5 unexpected success")
        except Exception:
            print("Test5 expected failure")
    finally:
        pass