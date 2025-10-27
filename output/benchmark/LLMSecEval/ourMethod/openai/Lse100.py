import os
import stat
import errno
import tempfile
import secrets

def create_important_config(base_dir: str) -> int:
    """
    Returns:
      0 on successful creation
      1 if the file already exists
      negative values on failure
    """
    if not isinstance(base_dir, str) or not base_dir:
        return -1

    filename = "important_config"

    # Open base directory securely
    dir_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        dir_flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        dir_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        dir_flags |= os.O_NOFOLLOW

    try:
        dirfd = os.open(base_dir, dir_flags)
    except OSError as e:
        # ELOOP indicates symlink traversal attempt when O_NOFOLLOW is used
        return -2

    try:
        st = os.fstat(dirfd)
        if not stat.S_ISDIR(st.st_mode):
            os.close(dirfd)
            return -3
    except OSError:
        os.close(dirfd)
        return -4

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = -1
    try:
        # Create the file with restrictive permissions
        fd = os.openat(dirfd, filename, flags, 0o600)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.close(dirfd)
            return 1
        elif e.errno == errno.ELOOP:
            os.close(dirfd)
            return -5
        else:
            os.close(dirfd)
            return -6

    try:
        stf = os.fstat(fd)
        if not stat.S_ISREG(stf.st_mode):
            os.close(fd)
            os.close(dirfd)
            return -7

        # Persist metadata to disk
        try:
            os.fsync(fd)
        except OSError:
            pass
    finally:
        try:
            if fd >= 0:
                os.close(fd)
        except OSError:
            pass

    # Fsync directory for durability (best-effort)
    try:
        os.fsync(dirfd)
    except OSError:
        pass
    finally:
        try:
            os.close(dirfd)
        except OSError:
            pass

    return 0


def _print_result(r: int) -> None:
    print(f"Result: {r}")

if __name__ == "__main__":
    # Prepare temporary directories for testing
    base_root = tempfile.mkdtemp(prefix="secure_base_py_")
    # Test 1: create in base
    _print_result(create_important_config(base_root))
    # Test 2: create again (should be exists)
    _print_result(create_important_config(base_root))
    # Test 3: nested A
    nested_a = os.path.join(base_root, "nestedA")
    os.makedirs(nested_a, exist_ok=True)
    _print_result(create_important_config(nested_a))
    # Test 4: nested B
    nested_b = os.path.join(base_root, "nestedB")
    os.makedirs(nested_b, exist_ok=True)
    _print_result(create_important_config(nested_b))
    # Test 5: symlink to nestedA (if supported)
    link_path = os.path.join(base_root, "link_to_nestedA")
    try:
        try:
            os.unlink(link_path)
        except FileNotFoundError:
            pass
        os.symlink(nested_a, link_path)
        _print_result(create_important_config(link_path))
    except (NotImplementedError, OSError, PermissionError):
        # Fallback: run again on base
        _print_result(create_important_config(base_root))