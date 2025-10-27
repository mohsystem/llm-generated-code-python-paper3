import os
import sys
import stat

def create_secret_file(filename: str, content: str) -> bool:
    if not filename or os.path.isabs(filename) or os.path.basename(filename) != filename:
        return False  # disallow absolute paths or traversal

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    mode = 0o600

    fd = None
    try:
        fd = os.open(filename, flags, mode)
        # Write content securely
        data = content.encode("utf-8", errors="strict")
        total = 0
        while total < len(data):
            written = os.write(fd, data[total:])
            if written <= 0:
                raise OSError("write failed")
            total += written
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, NotImplementedError):
            pass
    except Exception:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
    # Ensure restrictive perms post-creation on platforms without fchmod
    try:
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass
    return True

if __name__ == "__main__":
    secret = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    print(create_secret_file("secret.txt", secret))
    print(create_secret_file("secret1.txt", secret))
    print(create_secret_file("secret2.txt", secret))
    print(create_secret_file("secret3.txt", secret))
    print(create_secret_file("secret4.txt", secret))