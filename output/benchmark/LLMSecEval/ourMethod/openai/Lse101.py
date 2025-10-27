import os
import stat
import secrets

def write_important_config(base_dir: str) -> bool:
    if not isinstance(base_dir, str) or len(base_dir) == 0 or len(base_dir) > 4096:
        return False

    dir_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        dir_flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        dir_flags |= os.O_CLOEXEC

    try:
        dirfd = os.open(base_dir, dir_flags)
    except OSError:
        return False

    try:
        st = os.fstat(dirfd)
        if not stat.S_ISDIR(st.st_mode):
            os.close(dirfd)
            return False

        attempts = 10
        temp_name = None
        fd = -1
        while attempts > 0:
            attempts -= 1
            temp_name = f".impconf.{secrets.token_hex(8)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            try:
                fd = os.openat(dirfd, temp_name, flags, 0o600)
                break
            except FileExistsError:
                continue
            except OSError:
                temp_name = None
                break

        if fd < 0 or temp_name is None:
            os.close(dirfd)
            return False

        try:
            stf = os.fstat(fd)
            if not stat.S_ISREG(stf.st_mode):
                os.close(fd)
                try:
                    os.unlink(temp_name, dir_fd=dirfd)
                except OSError:
                    pass
                os.close(dirfd)
                return False

            data = b"important_config"
            total = 0
            while total < len(data):
                try:
                    w = os.write(fd, data[total:])
                except OSError:
                    w = -1
                if w <= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    try:
                        os.unlink(temp_name, dir_fd=dirfd)
                    except OSError:
                        pass
                    os.close(dirfd)
                    return False
                total += w

            try:
                os.fsync(fd)
            except OSError:
                pass

            try:
                os.close(fd)
            except OSError:
                pass

            try:
                os.rename(temp_name, "important_config", src_dir_fd=dirfd, dst_dir_fd=dirfd)
            except OSError:
                try:
                    os.unlink(temp_name, dir_fd=dirfd)
                except OSError:
                    pass
                os.close(dirfd)
                return False

            try:
                os.fsync(dirfd)
            except OSError:
                pass

            os.close(dirfd)
            return True

        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            try:
                if temp_name is not None:
                    os.unlink(temp_name, dir_fd=dirfd)
            except Exception:
                pass
            os.close(dirfd)
            return False

    except Exception:
        try:
            os.close(dirfd)
        except Exception:
            pass
        return False

if __name__ == "__main__":
    tests = [
        ".",
        "py_out1",
        "py_out1/subdir",
        "py out 2",
        "py_out3"
    ]
    for t in tests:
        try:
            os.makedirs(t, exist_ok=True)
        except Exception:
            pass
        res = write_important_config(t)
        print(f"{t}: {'ok' if res else 'fail'}")