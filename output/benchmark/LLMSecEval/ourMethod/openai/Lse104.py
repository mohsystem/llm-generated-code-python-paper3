import os
import errno
import tempfile

MAX_PATH_LEN = 4096
CONTENT = b"important_config"

def _split_components(rel_path: str):
    parts = rel_path.split("/")
    for p in parts:
        if p == "" or p == "." or p == "..":
            return None
    return parts

def secure_write_important_config(base_dir: str, rel_path: str) -> bool:
    if not isinstance(base_dir, str) or not isinstance(rel_path, str):
        return False
    if len(base_dir) == 0 or len(rel_path) == 0:
        return False
    if "\x00" in base_dir or "\x00" in rel_path:
        return False
    if len(rel_path) > MAX_PATH_LEN:
        return False
    if os.path.isabs(rel_path):
        return False

    parts = _split_components(rel_path)
    if parts is None:
        return False

    try:
        # Open base directory safely
        base_fd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            st = os.fstat(base_fd)
            if not os.path.S_ISDIR(st.st_mode):
                return False
        except Exception:
            os.close(base_fd)
            return False
    except Exception:
        return False

    # Traverse components to get parent directory fd
    dir_fd = base_fd
    try:
        for comp in parts[:-1]:
            try:
                nfd = os.openat(dir_fd, comp,
                                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
            except OSError as e:
                if dir_fd != base_fd:
                    os.close(dir_fd)
                os.close(base_fd)
                return False
            try:
                st = os.fstat(nfd)
                if not os.path.S_ISDIR(st.st_mode):
                    os.close(nfd)
                    if dir_fd != base_fd:
                        os.close(dir_fd)
                    os.close(base_fd)
                    return False
            except Exception:
                os.close(nfd)
                if dir_fd != base_fd:
                    os.close(dir_fd)
                os.close(base_fd)
                return False
            if dir_fd != base_fd:
                os.close(dir_fd)
            dir_fd = nfd

        final_name = parts[-1]
        if len(final_name) == 0 or len(final_name) > 255:
            if dir_fd != base_fd:
                os.close(dir_fd)
            os.close(base_fd)
            return False

        # Refuse if destination is a symlink (best-effort): lstat without following
        try:
            st = os.fstatat(dir_fd, final_name, os.AT_SYMLINK_NOFOLLOW)
            # If exists and is symlink, reject
            if os.path.S_ISLNK(st.st_mode):
                if dir_fd != base_fd:
                    os.close(dir_fd)
                os.close(base_fd)
                return False
        except AttributeError:
            # fstatat may not be available; best-effort skip
            pass
        except FileNotFoundError:
            pass
        except OSError as e:
            if e.errno not in (errno.ENOENT,):
                if dir_fd != base_fd:
                    os.close(dir_fd)
                os.close(base_fd)
                return False

        # Create a unique temp file in the target directory
        rand = os.urandom(8).hex()
        tmp_name = f".tmp-{rand}-{os.getpid()}"

        try:
            tfd = os.openat(dir_fd, tmp_name,
                            os.O_RDWR | os.O_CREAT | os.O_EXCL |
                            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                            0o600)
        except OSError:
            if dir_fd != base_fd:
                os.close(dir_fd)
            os.close(base_fd)
            return False

        ok = False
        try:
            # Write content
            total = 0
            while total < len(CONTENT):
                n = os.write(tfd, CONTENT[total:])
                if n <= 0:
                    raise OSError("short write")
                total += n
            os.fsync(tfd)
            # Close before rename
            os.close(tfd)
            tfd = -1

            # Atomic rename within same directory
            try:
                os.rename(tmp_name, final_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            except TypeError:
                # Older Python: fallback not available
                # Remove temp and fail closed
                os.unlink(tmp_name, dir_fd=dir_fd)  # type: ignore
                if dir_fd != base_fd:
                    os.close(dir_fd)
                os.close(base_fd)
                return False

            # fsync the directory to persist rename
            os.fsync(dir_fd)
            ok = True
        finally:
            if 'tfd' in locals() and isinstance(tfd, int) and tfd >= 0:
                try:
                    os.close(tfd)
                except Exception:
                    pass
            # Ensure temp removed on failure
            if not ok:
                try:
                    os.unlink(tmp_name, dir_fd=dir_fd)  # type: ignore
                except Exception:
                    pass

        if dir_fd != base_fd:
            os.close(dir_fd)
        os.close(base_fd)
        return True
    except Exception:
        try:
            if dir_fd != base_fd:
                os.close(dir_fd)
        except Exception:
            pass
        try:
            os.close(base_fd)
        except Exception:
            pass
        return False

if __name__ == "__main__":
    # Setup base directory and subdir
    base = tempfile.mkdtemp(prefix="safe-base-")
    subdir = os.path.join(base, "subdir")
    os.makedirs(subdir, exist_ok=True)

    tests = [
        "config.txt",            # True
        "subdir/settings.conf",  # True
        "../escape.txt",         # False
        "/abs/path.txt",         # False
        "nested/../final.conf",  # False
    ]

    for rel in tests:
        res = secure_write_important_config(base, rel)
        print(f"{rel} -> {'OK' if res else 'FAIL'}")