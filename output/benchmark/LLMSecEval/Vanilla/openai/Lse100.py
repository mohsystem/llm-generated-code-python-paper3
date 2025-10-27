import os
import stat

def ensure_config_file(path: str, mode: int = 0o600) -> bool:
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = None
    try:
        fd = os.open(path, flags, mode)
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    try:
        if os.name == "nt":
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        else:
            os.chmod(path, mode)
    except OSError:
        pass
    return os.path.exists(path)

def main():
    for i in range(1, 6):
        print(f"Test {i}: {ensure_config_file('important_config')}")

if __name__ == "__main__":
    main()