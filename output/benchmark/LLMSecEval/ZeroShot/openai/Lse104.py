import os
import stat

def write_important_config(file_path: str, content: str) -> int:
    if not isinstance(file_path, str) or not file_path:
        raise ValueError("Invalid file_path")
    if not isinstance(content, str):
        raise ValueError("Invalid content")

    flags = os.O_RDWR | os.O_CREAT
    # Add secure flags if available
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)

    mode = 0o600
    fd = None
    data = content.encode("utf-8")
    total_written = 0

    try:
        fd = os.open(file_path, flags, mode)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("Refusing to write to non-regular file")

        while total_written < len(data):
            try:
                n = os.write(fd, data[total_written:])
            except InterruptedError:
                continue
            if n == 0:
                raise OSError("Short write")
            total_written += n

        os.fsync(fd)
        return total_written
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass

if __name__ == "__main__":
    test_files = [
        "py_test_secure_1.cfg",
        "py_test_secure_2.cfg",
        "py_test_secure_3.cfg",
        "py_test_secure_4.cfg",
        "py_test_secure_5.cfg",
    ]
    for f in test_files:
        try:
            n = write_important_config(f, "important_config")
            print(f"Python wrote {n} bytes to {f}")
        except Exception as e:
            print(f"Python failed for {f}: {e}")