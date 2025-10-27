import os
import stat
import tempfile
import errno

MAX_SIZE = 8 * 1024 * 1024  # 8 MiB

class Result:
    def __init__(self, bytes_read: int, checksum: int, success: bool, message: str):
        self.bytes_read = bytes_read
        self.checksum = checksum
        self.success = success
        self.message = message
    def __repr__(self):
        return f"Result(bytes_read={self.bytes_read}, checksum={self.checksum}, success={self.success}, message='{self.message}')"

def _is_safe_rel_path(p: str) -> bool:
    if not p or p.startswith('/') or p.startswith('\\'):
        return False
    if '\x00' in p:
        return False
    for part in p.split('/'):
        if not part or part == '.' or part == '..' or '\\' in part:
            return False
    return True

def _ensure_dirs(dirfd: int, relpath: str) -> bool:
    parts = relpath.split('/')[:-1]
    curfd = dirfd
    subpath = ""
    for part in parts:
        subpath = part if not subpath else subpath + "/" + part
        try:
            os.mkdir(subpath, 0o700, dir_fd=dirfd)
        except FileExistsError:
            # verify it's a directory and not symlink
            try:
                st = os.stat(subpath, dir_fd=dirfd, follow_symlinks=False)
                if not stat.S_ISDIR(st.st_mode):
                    return False
            except OSError:
                return False
        except OSError:
            return False
    return True

def process_file(base_dir: str, input_rel: str, output_rel: str) -> Result:
    if not _is_safe_rel_path(input_rel) or not _is_safe_rel_path(output_rel):
        return Result(0, 0, False, "Invalid relative path")

    try:
        dirfd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return Result(0, 0, False, "Base directory open failed")

    try:
        # Open input securely
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            infd = os.open(input_rel, flags, dir_fd=dirfd)
        except OSError as e:
            return Result(0, 0, False, "Open input failed")
        try:
            st = os.fstat(infd)
            if not stat.S_ISREG(st.st_mode):
                return Result(0, 0, False, "Not a regular file")
            if st.st_size > MAX_SIZE:
                return Result(0, 0, False, "File too large")
            # Read and checksum
            bytes_read = 0
            checksum = 0
            while True:
                data = os.read(infd, 8192)
                if not data:
                    break
                bytes_read += len(data)
                checksum = (checksum + sum(data)) & 0xFFFFFFFF
        finally:
            try:
                os.close(infd)
            except Exception:
                pass

        # Prepare output directory structure
        if not _ensure_dirs(dirfd, output_rel):
            return Result(0, 0, False, "Failed to create directories")

        # Create a temp file in the same directory
        # Generate unique temp name
        for attempt in range(100):
            tmpname = f".tmp_{os.getpid()}_{attempt}_{os.urandom(4).hex()}"
            try:
                out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    out_flags |= os.O_NOFOLLOW
                tmpfd = os.open(tmpname, out_flags, 0o600, dir_fd=dirfd)
                tmp_rel = tmpname
                break
            except FileExistsError:
                continue
            except OSError:
                return Result(0, 0, False, "Temp create failed")
        else:
            return Result(0, 0, False, "Temp create failed")

        try:
            out_data = f"{bytes_read},{checksum}\n".encode("utf-8")
            off = 0
            while off < len(out_data):
                n = os.write(tmpfd, out_data[off:])
                if n <= 0:
                    return Result(0, 0, False, "Write failed")
                off += n
            os.fsync(tmpfd)
        finally:
            try:
                os.close(tmpfd)
            except Exception:
                pass

        # Atomic move into place
        try:
            os.rename(tmp_rel, output_rel, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        except OSError:
            # try to replace
            try:
                # remove destination if exists, then rename
                try:
                    os.unlink(output_rel, dir_fd=dirfd)
                except FileNotFoundError:
                    pass
                os.rename(tmp_rel, output_rel, src_dir_fd=dirfd, dst_dir_fd=dirfd)
            except OSError:
                # cleanup temp
                try:
                    os.unlink(tmp_rel, dir_fd=dirfd)
                except Exception:
                    pass
                return Result(0, 0, False, "Rename failed")

        # fsync directory
        try:
            os.fsync(dirfd)
        except Exception:
            pass

        return Result(bytes_read, checksum, True, "OK")
    finally:
        try:
            os.close(dirfd)
        except Exception:
            pass

def _write_file(base_dir: str, rel: str, data: bytes):
    dirfd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        # ensure dirs
        parts = rel.split('/')[:-1]
        for i in range(len(parts)):
            sub = "/".join(parts[:i+1])
            try:
                os.mkdir(sub, 0o700, dir_fd=dirfd)
            except FileExistsError:
                pass
        fd = os.open(rel, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600, dir_fd=dirfd)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)

if __name__ == "__main__":
    base = tempfile.mkdtemp(prefix="secure_io_base_")
    print("Base dir:", base)

    # Prepare test input files
    _write_file(base, "empty.txt", b"")
    _write_file(base, "hello.txt", b"Hello, World!")
    _write_file(base, "zeros.bin", b"\x00" * 1024)
    _write_file(base, "repeated.txt", b"abc" * 1000)

    # Test cases
    r1 = process_file(base, "empty.txt", "out/out1.txt")
    print("Test1:", r1)

    r2 = process_file(base, "hello.txt", "out/out2.txt")
    print("Test2:", r2)

    r3 = process_file(base, "zeros.bin", "out/out3.txt")
    print("Test3:", r3)

    r4 = process_file(base, "repeated.txt", "out/out4.txt")
    print("Test4:", r4)

    r5 = process_file(base, "../evil.txt", "out/out5.txt")
    print("Test5:", r5)