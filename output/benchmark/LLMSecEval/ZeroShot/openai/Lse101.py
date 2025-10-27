import os

def write_important_config(content: str) -> bool:
    filename = "important_config"
    fixed_content = "important_config"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow
    try:
        fd = os.open(filename, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            os.write(fd, fixed_content.encode("utf-8"))
            return True
        finally:
            os.close(fd)
    except OSError:
        try:
            if os.path.islink(filename):
                return False
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                os.write(fd, fixed_content.encode("utf-8"))
                return True
            finally:
                os.close(fd)
        except OSError:
            return False

if __name__ == "__main__":
    print(write_important_config("important_config"))
    print(write_important_config("important_config"))
    print(write_important_config("important_config"))
    print(write_important_config("important_config"))
    print(write_important_config("important_config"))