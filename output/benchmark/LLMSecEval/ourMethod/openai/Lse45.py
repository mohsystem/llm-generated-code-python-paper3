import os
import stat
from typing import Tuple

MAX_SIZE = 1 << 20  # 1 MiB
MAX_COMPONENTS = 64
MAX_COMPONENT_LEN = 255

def _validate_relative_path(requested_path: str) -> None:
    if requested_path is None:
        raise ValueError("Invalid path")
    if len(requested_path) == 0 or len(requested_path) > 4096:
        raise ValueError("Invalid path length")
    if '\x00' in requested_path:
        raise ValueError("Invalid character")
    if os.path.isabs(requested_path):
        raise ValueError("Path must be relative")

    # Only allow simple safe characters
    for ch in requested_path:
        if not (ch.isalnum() or ch in ('/', '.', '-', '_', ' ')):
            raise ValueError("Invalid characters")

    comps = requested_path.split('/')
    if len(comps) > MAX_COMPONENTS:
        raise ValueError("Too many components")
    for c in comps:
        if c in ('', '.', '..'):
            raise ValueError("Invalid path component")
        if len(c) > MAX_COMPONENT_LEN:
            raise ValueError("Component too long")

def read_safe_file(base_dir: str, requested_path: str, max_size: int = MAX_SIZE) -> bytes:
    if not isinstance(base_dir, str) or not isinstance(requested_path, str):
        raise ValueError("Invalid arguments")
    if max_size <= 0 or max_size > (64 << 20):
        raise ValueError("Invalid max size")

    _validate_relative_path(requested_path)

    # Open base directory without following symlinks
    dfd = -1
    fd = -1
    try:
        dfd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0), dir_fd=None, follow_symlinks=False)
    except Exception as e:
        # Fallback without O_DIRECTORY where unsupported
        try:
            dfd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0), dir_fd=None, follow_symlinks=False)
            # Verify it's a directory
            st = os.fstat(dfd)
            if not stat.S_ISDIR(st.st_mode):
                raise OSError("Base is not directory")
        except Exception:
            if dfd != -1:
                try:
                    os.close(dfd)
                except Exception:
                    pass
            raise

    try:
        # Open the requested file relative to base directory, do not follow symlinks
        fd = os.open(requested_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd, follow_symlinks=False)

        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("Not a regular file")
        if st.st_size < 0 or st.st_size > max_size:
            raise OSError("File too large")

        # Read the file safely
        remaining = int(min(st.st_size, max_size))
        chunks = []
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)

        data = b''.join(chunks)
        return data
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except Exception:
                pass
        if dfd != -1:
            try:
                os.close(dfd)
            except Exception:
                pass

def _write_file(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def main():
    import tempfile
    import shutil

    base = tempfile.mkdtemp(prefix="safe_dir_")
    try:
        # Prepare files
        _write_file(os.path.join(base, "a.txt"), b"Hello from a.txt")
        os.makedirs(os.path.join(base, "sub"), exist_ok=True)
        _write_file(os.path.join(base, "sub", "x.txt"), b"Nested file content")

        # Outside file for symlink
        outside = os.path.join(os.path.dirname(base), "outside.txt")
        try:
            _write_file(outside, b"outside")
        except Exception:
            pass
        evil_link = os.path.join(base, "evil_link")
        try:
            if os.path.lexists(evil_link):
                os.unlink(evil_link)
            os.symlink(outside, evil_link)
        except Exception:
            pass  # symlink may not be available

        tests = [
            "a.txt",         # valid
            "sub/x.txt",     # valid nested
            "../etc/passwd", # traversal
            "evil_link",     # symlink
            "sub"            # directory
        ]

        for t in tests:
            try:
                data = read_safe_file(base, t)
                preview = data.decode("utf-8", errors="replace")
                if len(preview) > 80:
                    preview = preview[:80]
                print(f"OK: {t} => {preview}")
            except Exception:
                print(f"FAIL: {t}")
    finally:
        try:
            shutil.rmtree(base, ignore_errors=True)
        except Exception:
            pass

if __name__ == "__main__":
    main()