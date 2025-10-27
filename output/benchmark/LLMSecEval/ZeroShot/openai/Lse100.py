import os

def create_secure_file(path, mode=0o600):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = None
    try:
        fd = os.open(path, flags, mode)
        try:
            os.fchmod(fd, mode)
        except AttributeError:
            os.chmod(path, mode)
        return True
    except FileExistsError:
        return False
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

if __name__ == "__main__":
    tests = [
        "important_config",
        "important_config_1",
        "important_config_2",
        "important_config",
        "important_config_3"
    ]
    for t in tests:
        print(f"{t}:{create_secure_file(t)}")