import os

def secure_open_and_write(filename: str, content: str) -> str:
    # Pre-check for symlink if possible
    try:
        st = os.lstat(filename)
        if os.path.islink(filename):
            raise OSError(f"Refusing to operate on a symbolic link: {filename}")
    except FileNotFoundError:
        pass

    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)

    mode = 0o644
    fd = None
    try:
        fd = os.open(filename, flags, mode)
        # Enforce permissions regardless of umask (best effort)
        try:
            os.fchmod(fd, mode)
        except AttributeError:
            pass

        # Truncate to write exactly the provided content
        os.ftruncate(fd, 0)
        data = content.encode("utf-8")
        total = 0
        while total < len(data):
            n = os.write(fd, data[total:])
            if n is None or n <= 0:
                raise OSError("write failed")
            total += n

        os.lseek(fd, 0, os.SEEK_SET)

        chunks = []
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass

if __name__ == "__main__":
    filename = "important_config"
    content = "important_config"
    for i in range(5):
        try:
            result = secure_open_and_write(filename, content)
            print(f"Test {i+1}: {result}")
        except Exception as e:
            print(f"Error: {e}")