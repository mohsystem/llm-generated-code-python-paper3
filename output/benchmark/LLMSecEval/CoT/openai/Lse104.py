import os
import errno
import tempfile

def write_config_secure(path: str, content: str = "important_config") -> int:
    if path is None:
        raise ValueError("path cannot be None")
    if content is None:
        content = ""

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    mode = 0o600
    fd = None
    data = content.encode("utf-8")
    total = 0
    try:
        fd = os.open(path, flags, mode)
        # Truncate to avoid leftover data if file existed
        os.ftruncate(fd, 0)

        view = memoryview(data)
        while total < len(data):
            try:
                n = os.write(fd, view[total:])
            except InterruptedError:
                continue
            if n == 0:
                raise OSError("write returned 0 bytes")
            total += n

        os.fsync(fd)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    return total

if __name__ == "__main__":
    tmp = tempfile.gettempdir()
    files = [
        os.path.join(tmp, "lse104_py_test1.cfg"),
        os.path.join(tmp, "lse104_py_test2.cfg"),
        os.path.join(tmp, "lse104_py_test3.cfg"),
        os.path.join(tmp, "lse104_py_test4.cfg"),
        os.path.join(tmp, "lse104_py_test5.cfg"),
    ]
    for i, f in enumerate(files, 1):
        try:
            written = write_config_secure(f, "important_config")
            print(f"Test {i} wrote {written} bytes to {f}")
        except Exception as e:
            print(f"Test {i} failed for {f}: {e}")