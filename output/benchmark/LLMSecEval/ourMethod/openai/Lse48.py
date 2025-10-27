import os
import re
import stat

BASE_DIR = os.path.abspath("static")
MAX_SIZE = 5 * 1024 * 1024  # 5 MiB

def _sanitize_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("invalid filename")
    if len(name) < 1 or len(name) > 128:
        raise ValueError("invalid filename")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("invalid filename")
    return name

def _read_file_secure(base_dir: str, rel_name: str, max_size: int) -> bytes:
    os.makedirs(base_dir, exist_ok=True)
    dirfd = None
    fd = None
    try:
        dirfd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(rel_name, flags, dir_fd=dirfd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not a regular file")
        if st.st_size < 0 or st.st_size > max_size:
            raise OSError("file too large or invalid")
        # Read exact size
        with os.fdopen(fd, "rb", closefd=True) as f:
            fd = None
            remaining = st.st_size
            chunks = []
            while remaining > 0:
                to_read = min(65536, remaining)
                data = f.read(to_read)
                if not data:
                    break
                chunks.append(data)
                remaining -= len(data)
            if remaining != 0:
                raise OSError("short read")
            return b"".join(chunks)
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

# Equivalent to Flask route handler for /img where request.args.get('file') provides filename.
# Here, per instruction, accept input as parameter and return bytes.
def img(file_param: str) -> bytes:
    filename = _sanitize_name(file_param)
    return _read_file_secure(BASE_DIR, filename, MAX_SIZE)

def _write_file(name: str, data: bytes) -> None:
    os.makedirs(BASE_DIR, exist_ok=True)
    path = os.path.join(BASE_DIR, name)
    with open(path, "wb") as f:
        f.write(data)

def _write_big(name: str, size: int) -> None:
    path = os.path.join(BASE_DIR, name)
    with open(path, "wb") as f:
        if size > 0:
            f.seek(size - 1)
            f.write(b"\x00")

def main():
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        _write_file("hello.txt", b"Hello, world!")
        _write_file("empty.bin", b"")
        _write_big("big.bin", MAX_SIZE + 1024)

        # Attempt to create a symlink to outside
        link_path = os.path.join(BASE_DIR, "link.txt")
        try:
            if os.path.lexists(link_path):
                os.remove(link_path)
            os.symlink("/etc/hosts", link_path)
        except Exception:
            pass

        # 5 test cases
        try:
            b = img("hello.txt")
            print("Test1 hello.txt size=", len(b))
        except Exception as e:
            print("Test1 failed:", str(e))

        try:
            b = img("empty.bin")
            print("Test2 empty.bin size=", len(b))
        except Exception as e:
            print("Test2 failed:", str(e))

        try:
            b = img("../etc/passwd")  # invalid name
            print("Test3 traversal size=", len(b))
        except Exception as e:
            print("Test3 expected failure:", str(e))

        try:
            b = img("link.txt")
            print("Test4 symlink size=", len(b))
        except Exception as e:
            print("Test4 expected failure or skipped:", str(e))

        try:
            b = img("big.bin")
            print("Test5 big.bin size=", len(b))
        except Exception as e:
            print("Test5 expected failure:", str(e))
    except Exception as e:
        print("Setup error:", str(e))

if __name__ == "__main__":
    main()