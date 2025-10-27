import os
import stat
import tempfile
import secrets
from typing import Optional

def _validate_filename(name: str) -> None:
    if not isinstance(name, str):
        raise ValueError("Invalid filename")
    if len(name) == 0 or len(name) > 255:
        raise ValueError("Invalid filename length")
    if name in (".", ".."):
        raise ValueError("Invalid filename")
    if "/" in name or "\\" in name:
        raise ValueError("Invalid filename characters")
    import re
    if re.fullmatch(r"[A-Za-z0-9._-]+", name) is None:
        raise ValueError("Filename contains disallowed characters")

def _open_dirfd_secure(base_dir: str) -> int:
    if not isinstance(base_dir, str) or len(base_dir) == 0:
        raise ValueError("Invalid base directory")
    # Use O_NOFOLLOW if available to avoid following symlinks
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    dirfd = os.open(base_dir, flags)
    st = os.fstat(dirfd)
    if not stat.S_ISDIR(st.st_mode):
        os.close(dirfd)
        raise OSError("Base path is not a directory")
    return dirfd

def create_secret_file(base_dir: str, filename: str, content: str) -> str:
    """
    Creates base_dir/filename, writing content securely, then sets restrictive permissions (0600).
    Returns the absolute path to the created file.
    """
    _validate_filename(filename)
    dirfd = _open_dirfd_secure(base_dir)

    # Create a randomized temp file name inside base_dir
    tmp_name = ".tmp." + secrets.token_hex(16)

    # Prepare flags and mode for secure creation
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    mode = 0o600

    fd = None
    try:
        fd = os.openat(dirfd, tmp_name, flags, mode)
        data = content.encode("utf-8")
        # Write all bytes
        total = 0
        while total < len(data):
            n = os.write(fd, data[total:])
            if n <= 0:
                raise OSError("Write failed")
            total += n
        # Ensure on-disk
        os.fsync(fd)

        # Atomically move into place within the same directory
        os.replace(tmp_name, filename, src_dir_fd=dirfd, dst_dir_fd=dirfd)

        # Enforce restrictive permissions (already 0600 at creation, ensure again)
        try:
            os.fchmod(fd, 0o600)
        except Exception:
            pass

        # fsync the directory to persist the rename
        os.fsync(dirfd)

        # Return final absolute path without trusting external changes
        abs_path = os.path.abspath(os.path.join(base_dir, filename))
        return abs_path
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            os.close(dirfd)
        except Exception:
            pass

if __name__ == "__main__":
    CONTENT = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    results = []
    for i in range(5):
        base = tempfile.mkdtemp(prefix=f"secure_secret_test_{i+1}_")
        try:
            p = create_secret_file(base, "secret.txt", CONTENT)
            st = os.stat(p, follow_symlinks=False)
            ok = stat.S_ISREG(st.st_mode) and (st.st_size == len(CONTENT.encode("utf-8")))
            print(f"Test {i+1} {'OK' if ok else 'FAILED'}: {p}")
        except Exception:
            print(f"Test {i+1} FAILED")