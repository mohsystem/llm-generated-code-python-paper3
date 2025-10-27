import os
import stat

def secure_open_write(path: str, create: bool, trunc: bool, wr_only: bool, excl: bool) -> bool:
    try:
        if excl and not create:
            return False

        parent = os.path.dirname(os.path.abspath(path))
        if parent and not os.path.exists(parent):
            try:
                os.makedirs(parent, mode=0o700, exist_ok=True)
            except OSError:
                return False

        flags = 0
        # Prevent fd leaks and avoid following symlinks
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        flags |= os.O_WRONLY if wr_only else os.O_RDWR

        if create:
            flags |= os.O_CREAT
        if excl:
            flags |= os.O_EXCL
        if trunc:
            flags |= os.O_TRUNC

        mode = 0o600
        fd = os.open(path, flags, mode)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return False
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

        return True
    except OSError:
        return False

if __name__ == "__main__":
    base = "lse103_tmp_py"
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
    except OSError:
        pass

    f1 = os.path.join(base, "a.txt")
    f2 = os.path.join(base, "nonexist.txt")

    print(secure_open_write(f1, True, False, True, True))
    print(secure_open_write(f1, True, False, True, True))
    print(secure_open_write(f1, False, True, True, False))
    print(secure_open_write(f1, False, False, True, False))
    print(secure_open_write(f2, False, False, True, False))