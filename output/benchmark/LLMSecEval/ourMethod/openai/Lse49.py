import os
import stat
import sys
import tarfile
from typing import Optional

MAX_FILE_SIZE = 1_000_000_000  # 1GB
BLOCK_SIZE = 512

def _is_safe_relative(path: str) -> bool:
    if not path or path.startswith("/"):
        return False
    parts = path.split("/")
    for seg in parts:
        if seg in ("", ".", ".."):
            return False
    return True

def _mkdirs_at(base_fd: int, rel_dir: str) -> int:
    # Walk and create directories under base_fd; return fd of the final dir (CLOEXEC)
    current_fd = os.dup(base_fd)
    try:
        if rel_dir == "":
            return current_fd
        for seg in rel_dir.split("/"):
            if seg in ("", ".", ".."):
                os.close(current_fd)
                raise OSError("invalid segment")
            try:
                next_fd = os.open(seg, os.O_RDONLY | os.O_CLOEXEC, dir_fd=current_fd)
                st = os.fstat(next_fd)
                if not stat.S_ISDIR(st.st_mode):
                    os.close(next_fd)
                    os.close(current_fd)
                    raise OSError("non-directory in path")
            except FileNotFoundError:
                os.mkdir(seg, 0o700, dir_fd=current_fd)
                next_fd = os.open(seg, os.O_RDONLY | os.O_CLOEXEC, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except:
        raise

def extract_tar_secure(archive_path: str, dest_dir: str) -> None:
    if not isinstance(archive_path, str) or not isinstance(dest_dir, str):
        raise ValueError("invalid input types")
    # Prepare destination
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    dest_fd = os.open(dest_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        st_dest = os.fstat(dest_fd)
        if not stat.S_ISDIR(st_dest.st_mode):
            raise OSError("destination not a directory")
        # Open archive safely
        flags = os.O_RDONLY | os.O_CLOEXEC
        # O_NOFOLLOW is not available on all platforms; try to use it if present
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        a_fd = os.open(archive_path, flags)
        try:
            st = os.fstat(a_fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file")
            fileobj = os.fdopen(a_fd, "rb")
            # tarfile open: generic reader
            with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
                for m in tf.getmembers():
                    name = m.name
                    if not isinstance(name, str):
                        continue
                    # Normalize tar path style
                    name = name.replace("\\", "/")
                    if not _is_safe_relative(name):
                        continue
                    # Only allow regular files and directories
                    if m.isdir():
                        # create directories securely
                        dir_fd = _mkdirs_at(dest_fd, name)
                        os.close(dir_fd)
                        continue
                    if not m.isreg():
                        continue
                    if m.size < 0 or m.size > MAX_FILE_SIZE:
                        continue
                    # Ensure parent directories
                    parent = ""
                    base = name
                    if "/" in name:
                        parent, base = name.rsplit("/", 1)
                    parent_fd = dest_fd
                    close_parent = False
                    if parent:
                        parent_fd = _mkdirs_at(dest_fd, parent)
                        close_parent = True
                    try:
                        # Create file securely
                        oflags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                        if hasattr(os, "O_NOFOLLOW"):
                            oflags |= os.O_NOFOLLOW
                        ffd = os.open(base, oflags, dir_fd=parent_fd, mode=0o600)
                        try:
                            stf = os.fstat(ffd)
                            if not stat.S_ISREG(stf.st_mode):
                                raise OSError("not regular after open")
                            src = tf.extractfile(m)
                            if src is None:
                                raise OSError("cannot get file stream")
                            remaining = m.size
                            bufsize = 8192
                            while remaining > 0:
                                chunk = src.read(min(bufsize, remaining))
                                if not chunk:
                                    raise OSError("unexpected EOF")
                                os.write(ffd, chunk)
                                remaining -= len(chunk)
                            os.fsync(ffd)
                            src.close()
                        finally:
                            os.close(ffd)
                    finally:
                        if close_parent:
                            os.close(parent_fd)
            # fileobj closed by context manager; do not close a_fd again
        except:
            # ensure the fd is closed if tarfile.open fails early
            try:
                os.close(a_fd)
            except Exception:
                pass
            raise
    finally:
        try:
            # fsync destination dir to persist entries
            try:
                os.fsync(dest_fd)
            except Exception:
                pass
            os.close(dest_fd)
        except Exception:
            pass

def _run_tests():
    tests = [
        ("archive.zip", "/tmp/unpack"),
        ("./archive.zip", "/tmp/unpack"),
        ("/does/not/exist/archive.zip", "/tmp/unpack"),
        ("archive.zip", "/tmp/unpack"),
        ("archive.zip", "/tmp/unpack"),
    ]
    for i, (a, d) in enumerate(tests, 1):
        try:
            extract_tar_secure(a, d)
            print(f"Test {i}: OK")
        except Exception as e:
            print(f"Test {i}: {e}")

if __name__ == "__main__":
    _run_tests()