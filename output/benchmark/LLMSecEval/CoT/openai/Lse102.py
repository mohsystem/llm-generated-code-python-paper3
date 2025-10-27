import os

# Chain-of-Through Step 1: Problem understanding & function signature
# Opens/creates file with 0644 and writes provided content, returns bytes written.
def secure_open_write(file_name: str, content: str) -> int:
    if file_name is None or content is None:
        raise ValueError("file_name/content cannot be None")

    flags = os.O_RDWR | os.O_CREAT
    # Chain-of-Through Step 2: Security requirements
    # Add secure flags if available
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    mode = 0o644
    fd = None
    total_written = 0
    try:
        # Chain-of-Through Step 3: Secure coding generation
        fd = os.open(file_name, flags, mode)

        # Explicitly set permissions to 0644 to counter umask
        try:
            os.fchmod(fd, 0o644)
        except AttributeError:
            pass  # fchmod might not be available on some platforms

        # Ensure it's a regular file
        try:
            st = os.fstat(fd)
            if not (st.st_mode & 0o170000 == 0o100000):  # S_IFREG
                raise OSError("Refusing to write to non-regular file")
        except Exception:
            raise

        data = content.encode("utf-8")
        view = memoryview(data)
        while total_written < len(data):
            try:
                n = os.write(fd, view[total_written:])
            except InterruptedError:
                continue
            if n <= 0:
                raise OSError("write failed")
            total_written += n

        try:
            os.fsync(fd)
        except Exception:
            pass

        return total_written
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ("important_config", "important_config"),
        ("important_config_1", "important_config"),
        ("important_config_2", "important_config"),
        ("important_config", "important_config"),
        ("important_config_readwrite", "important_config"),
    ]
    for i, (fname, content) in enumerate(tests, 1):
        try:
            n = secure_open_write(fname, content)
            print(f"Test {i}: Wrote {n} bytes to {fname}")
        except Exception as e:
            print(f"Test {i} failed for {fname}: {e}")