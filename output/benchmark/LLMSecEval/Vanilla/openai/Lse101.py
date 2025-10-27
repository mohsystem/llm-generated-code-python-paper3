import os

def write_important_config(path, content):
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o644
        fd = os.open(path, flags, mode)
        try:
            os.write(fd, content.encode('utf-8'))
            try:
                os.fchmod(fd, mode)  # Ensures permissions even if umask modified creation
            except AttributeError:
                os.chmod(path, mode)
        finally:
            os.close(fd)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    for i in range(1, 6):
        print(f"Test {i}: {write_important_config('important_config', 'important_config')}")