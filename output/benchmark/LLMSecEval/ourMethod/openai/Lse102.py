import os
import stat
import tempfile

def write_important_config(base_dir: str) -> bool:
    """
    Opens or creates 'important_config' in base_dir with read/write, mode 0644,
    and writes the string 'important_config'. Returns True on success.
    """
    if not isinstance(base_dir, str) or not base_dir:
        return False

    try:
        # Open base directory safely
        odir_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        odir_flags |= getattr(os, "O_NOFOLLOW", 0)
        # O_DIRECTORY may not exist on all platforms
        odir_flags |= getattr(os, "O_DIRECTORY", 0)
        dfd = os.open(base_dir, odir_flags)
    except Exception:
        return False

    fd = None
    try:
        # Open target file securely with O_NOFOLLOW and create if missing
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.openat(dfd, "important_config", flags, 0o644)

        # Validate: must be a regular file
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return False

        # Truncate before write to avoid residual data
        os.ftruncate(fd, 0)

        data = b"important_config"
        total = 0
        while total < len(data):
            n = os.write(fd, data[total:])
            if n <= 0:
                return False
            total += n

        try:
            os.fsync(fd)
        except Exception:
            # Best-effort fsync; on some FS it may not be necessary
            pass

        return True
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            os.close(dfd)
        except Exception:
            pass

if __name__ == "__main__":
    # 5 test cases
    t1 = tempfile.mkdtemp(prefix="py_icase1_")
    print("Test1:", write_important_config(t1))

    # Test2: write again to same dir
    print("Test2:", write_important_config(t1))

    # Test3: baseDir is a file (should fail)
    t3fd, t3path = tempfile.mkstemp(prefix="py_icase3_", suffix=".tmp")
    os.close(t3fd)
    print("Test3:", write_important_config(t3path))

    # Test4: non-existent directory (should fail)
    t4 = os.path.join(t1, "nonexistent_subdir_do_not_create")
    print("Test4:", write_important_config(t4))

    # Test5: valid subdir
    t5 = tempfile.mkdtemp(prefix="py_icase5_")
    sub = os.path.join(t5, "conf")
    os.makedirs(sub, exist_ok=True)
    print("Test5:", write_important_config(sub))