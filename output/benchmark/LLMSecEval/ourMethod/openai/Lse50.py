import os
import sys
import stat
import tarfile

MAX_ENTRY_SIZE = 100 * 1024 * 1024  # 100MB per entry cap

def _is_safe_rel_path(p: str) -> bool:
    if not p or p.startswith("/") or "\\" in p or ".." in p:
        return False
    # Windows absolute-like guard
    if len(p) >= 2 and p[1] == ":":
        return False
    return True

def _open_dir_nofollow(path: str):
    flags = getattr(os, "O_RDONLY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow
    return os.open(path, flags | getattr(os, "O_DIRECTORY", 0))

def _mkdirs_at(base_fd: int, rel_path: str) -> bool:
    if not rel_path:
        return True
    parts = [p for p in rel_path.split("/") if p and p != "."]
    cur_fd = os.dup(base_fd)
    try:
        for part in parts:
            try:
                # try open existing directory without following symlinks
                dfd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=cur_fd)
                os.close(cur_fd)
                cur_fd = dfd
                continue
            except FileNotFoundError:
                pass
            except OSError as e:
                # ELOOP or not a directory
                os.close(cur_fd)
                return False
            try:
                os.mkdir(part, 0o700, dir_fd=cur_fd)
            except FileExistsError:
                # Could be a non-directory, try to open as directory next
                pass
            try:
                dfd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=cur_fd)
            except OSError:
                os.close(cur_fd)
                return False
            os.close(cur_fd)
            cur_fd = dfd
        return True
    finally:
        try:
            os.close(cur_fd)
        except Exception:
            pass

def extract_tar_secure(archive_path: str, dest_dir: str) -> bool:
    if not isinstance(archive_path, str) or not isinstance(dest_dir, str):
        sys.stderr.write("Invalid input\n")
        return False
    if len(archive_path) > 4096 or len(dest_dir) > 4096:
        sys.stderr.write("Path too long\n")
        return False
    try:
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        # open destination dir without following symlinks
        dest_fd = _open_dir_nofollow(dest_dir)
    except Exception:
        sys.stderr.write("Failed to prepare destination\n")
        return False

    try:
        # Open the archive as a tar, even if named .zip; autodetect format
        # Open file securely best-effort
        fdesc = os.open(archive_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        fobj = os.fdopen(fdesc, "rb")
    except Exception:
        try:
            os.close(dest_fd)
        except Exception:
            pass
        sys.stderr.write("Failed to open archive\n")
        return False

    try:
        with fobj:
            try:
                with tarfile.open(fileobj=fobj, mode="r:*") as tf:
                    for m in tf.getmembers():
                        # validate size and type
                        if m.size < 0 or m.size > MAX_ENTRY_SIZE:
                            sys.stderr.write("Entry too large or invalid\n")
                            return False
                        # build safe path
                        rel = m.name
                        if m.isdir():
                            typ = "dir"
                        elif m.isreg():
                            typ = "file"
                        else:
                            # Skip unsupported entry types for safety
                            # Still need to read/skip data for pax headers etc, but tarfile handles internally
                            continue

                        if not _is_safe_rel_path(rel):
                            sys.stderr.write("Unsafe path in archive\n")
                            return False

                        # Ensure directory hierarchy
                        parent = os.path.dirname(rel)
                        if parent and not _mkdirs_at(dest_fd, parent):
                            sys.stderr.write("Failed to create directories\n")
                            return False

                        if typ == "dir":
                            if not _mkdirs_at(dest_fd, rel):
                                sys.stderr.write("Failed to create directory\n")
                                return False
                            continue

                        # Regular file extraction without following symlinks
                        # Open target with O_CREAT|O_EXCL and O_NOFOLLOW
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                        try:
                            fd_out = os.open(os.path.basename(rel), flags, dir_fd=(os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=dest_fd) if parent else dest_fd), mode=0o600)
                            # If parent is opened, close it after open
                            if parent:
                                try:
                                    # reopen to close
                                    pfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=dest_fd)
                                    os.close(pfd)
                                except Exception:
                                    pass
                        except FileExistsError:
                            sys.stderr.write("Refusing to overwrite existing file\n")
                            return False
                        except Exception:
                            sys.stderr.write("Failed to create output file\n")
                            return False

                        try:
                            srcf = tf.extractfile(m)
                            if srcf is None:
                                os.close(fd_out)
                                sys.stderr.write("Failed to read file from archive\n")
                                return False
                            with srcf:
                                remaining = m.size
                                bufsize = 32768
                                while remaining > 0:
                                    to_read = bufsize if remaining > bufsize else remaining
                                    chunk = srcf.read(to_read)
                                    if not chunk:
                                        os.close(fd_out)
                                        sys.stderr.write("Truncated file data\n")
                                        return False
                                    # Ensure write all
                                    view = memoryview(chunk)
                                    total = 0
                                    while total < len(view):
                                        w = os.write(fd_out, view[total:])
                                        if w <= 0:
                                            os.close(fd_out)
                                            sys.stderr.write("Write error\n")
                                            return False
                                        total += w
                                    remaining -= len(chunk)
                            os.fsync(fd_out)
                        finally:
                            try:
                                os.close(fd_out)
                            except Exception:
                                pass

                    # fsync destination directory
                    try:
                        os.fsync(dest_fd)
                    except Exception:
                        pass
                    return True
            except tarfile.TarError:
                sys.stderr.write("Invalid tar archive\n")
                return False
    finally:
        try:
            os.close(dest_fd)
        except Exception:
            pass

def main():
    # 5 test cases
    print("Test1:", extract_tar_secure("archive.zip", "/tmp/unpack"))
    print("Test2:", extract_tar_secure("nonexistent.tar", "/tmp/unpack"))
    print("Test3:", extract_tar_secure("", "/tmp/unpack"))
    print("Test4:", extract_tar_secure("archive.zip", "/tmp/unpack/sub/.."))
    print("Test5:", extract_tar_secure("archive.zip", "/tmp/unpack"))

if __name__ == "__main__":
    main()