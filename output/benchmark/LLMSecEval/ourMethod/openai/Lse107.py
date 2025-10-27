import os
import stat
import secrets
import tempfile
import shutil

CONTENT = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
TARGET_NAME = "secret.txt"

def create_secret_and_print_permissions(base_dir: str) -> str:
    # Open base directory safely
    flags_dir = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags_dir |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags_dir |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags_dir |= os.O_NOFOLLOW

    try:
        dirfd = os.open(base_dir, flags_dir)
    except OSError:
        return "Error"

    try:
        st_dir = os.fstat(dirfd)
        if not stat.S_ISDIR(st_dir.st_mode):
            return "Error"

        # Create unique temp file within base directory
        tmp_name = None
        o_nofollow = getattr(os, "O_NOFOLLOW", 0)
        for _ in range(100):
            candidate = f".secret_tmp_{secrets.token_hex(8)}"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            try:
                fd = os.openat(dirfd, candidate, flags | o_nofollow, 0o600)
                tmp_name = candidate
                break
            except FileExistsError:
                continue
            except OSError as e:
                if getattr(e, 'errno', None) == getattr(os, "ELOOP", 40):
                    return "Error"
                continue

        if tmp_name is None:
            return "Error"

        try:
            os.write(fd, CONTENT.encode("utf-8"))
            if hasattr(os, "fsync"):
                os.fsync(fd)
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

        # fsync directory to persist temp file
        try:
            os.fsync(dirfd)
        except Exception:
            pass

        # Atomically replace/move into place
        try:
            os.replace(tmp_name, TARGET_NAME, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        except TypeError:
            # Older Python fallback without dir fds (less ideal)
            full_tmp = os.path.join(base_dir, tmp_name)
            full_tgt = os.path.join(base_dir, TARGET_NAME)
            os.replace(full_tmp, full_tgt)

        # Ensure restrictive perms on final file
        try:
            fd2 = os.openat(dirfd, TARGET_NAME, os.O_RDONLY | o_nofollow)
            try:
                os.fchmod(fd2, 0o600)
            finally:
                os.close(fd2)
        except Exception:
            pass

        # Stat final file without following symlinks
        st = os.stat(TARGET_NAME, dir_fd=dirfd, follow_symlinks=False)
        mode_str = stat.filemode(st.st_mode)
        perms_octal = format(st.st_mode & 0o7777, "04o")
        return f"Permissions: {mode_str} ({perms_octal})"
    except Exception:
        return "Error"
    finally:
        try:
            os.close(dirfd)
        except Exception:
            pass

if __name__ == "__main__":
    # 5 test cases: create 5 temporary directories and run
    results = []
    dirs = []
    try:
        for _ in range(5):
            d = tempfile.mkdtemp(prefix="safe_dir_")
            dirs.append(d)
            results.append((d, create_secret_and_print_permissions(d)))
        for d, r in results:
            print(f"Base: {d} -> {r}")
    finally:
        for d in dirs:
            try:
                shutil.rmtree(d)
            except Exception:
                pass