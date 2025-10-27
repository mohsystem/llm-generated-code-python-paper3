import os
import errno
import time
import tempfile

def create_or_truncate_write(path: str, data: bytes) -> int:
    # Analogous to O_CREAT | O_WRONLY | O_TRUNC
    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
    # Harden with CLOEXEC and NOFOLLOW if available
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    mode = 0o600
    fd = -1
    try:
        parent = os.path.dirname(path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        fd = os.open(path, flags, mode)
        total = 0
        while total < len(data):
            written = os.write(fd, data[total:])
            if written <= 0:
                return -1
            total += written
        try:
            os.fsync(fd)
        except Exception:
            pass
        return 0
    except OSError:
        return -1
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except Exception:
                pass

def create_exclusive_write(path: str, data: bytes) -> int:
    # Analogous to O_CREAT | O_WRONLY | O_EXCL
    flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    mode = 0o600
    fd = -1
    try:
        parent = os.path.dirname(path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        fd = os.open(path, flags, mode)
        total = 0
        while total < len(data):
            written = os.write(fd, data[total:])
            if written <= 0:
                return -1
            total += written
        try:
            os.fsync(fd)
        except Exception:
            pass
        return 0
    except OSError as e:
        if e.errno == errno.EEXIST:
            return 1  # exists
        return -1
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except Exception:
                pass

def _read_all(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return b""

if __name__ == "__main__":
    tmp = tempfile.gettempdir()
    nonce = str(time.time_ns())
    pathA = os.path.join(tmp, f"lse103_py_A_{nonce}.txt")
    pathB = os.path.join(tmp, f"lse103_py_B_{nonce}.txt")

    # 5 test cases
    r1 = create_exclusive_write(pathA, b"hello exclusive A")
    print("T1 ex-create A:", r1)

    r2 = create_exclusive_write(pathA, b"should fail")
    print("T2 ex-create A again:", r2)

    r3 = create_or_truncate_write(pathA, b"truncated A")
    print("T3 truncate-write A:", r3, "len=", len(_read_all(pathA)))

    r4 = create_or_truncate_write(pathB, b"new B")
    print("T4 create-or-truncate B:", r4, "len=", len(_read_all(pathB)))

    r5 = create_exclusive_write(pathB, b"should fail B")
    print("T5 ex-create B again:", r5)

    # cleanup
    try: os.remove(pathA)
    except Exception: pass
    try: os.remove(pathB)
    except Exception: pass