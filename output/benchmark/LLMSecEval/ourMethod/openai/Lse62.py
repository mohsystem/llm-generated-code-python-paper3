import os
import sys
import errno
import secrets

MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MiB

def _is_safe_relative(rel: str) -> bool:
    if not rel or os.path.isabs(rel):
        return False
    norm = os.path.normpath(rel)
    if norm.startswith("..") or "/../" in "/" + norm + "/":
        return False
    if "\x00" in rel:
        return False
    return True

def _resolve_under_base(base_dir: str, rel: str) -> str:
    full = os.path.normpath(os.path.join(base_dir, rel))
    base = os.path.abspath(base_dir)
    full_abs = os.path.abspath(full)
    if not full_abs.startswith(base + os.sep) and full_abs != base:
        raise OSError("Path escapes base directory")
    return full_abs

def _fsync_dir(dir_path: str) -> None:
    try:
        fd = os.open(dir_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass

def _open_dirfd(base_dir: str) -> int:
    flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_RDONLY", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return os.open(base_dir, flags)

def _safe_write_file_at(dirfd: int, rel: str, data: bytes) -> None:
    # Create parent directories
    full_rel = os.path.normpath(rel)
    parts = full_rel.split(os.sep)
    if len(parts) > 1:
        cur_fd = os.dup(dirfd)
        try:
            for comp in parts[:-1]:
                if comp in ("", ".", ".."):
                    raise OSError("Invalid path component")
                try:
                    os.mkdirat(cur_fd, comp, 0o700)
                except FileExistsError:
                    pass
                new_fd = os.openat(cur_fd, comp, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
                os.close(cur_fd)
                cur_fd = new_fd

            leaf = parts[-1]
            tmpname = leaf + ".tmp-" + secrets.token_hex(8)
            tmp_fd = os.openat(cur_fd, tmpname, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                os.write(tmp_fd, data)
                os.fsync(tmp_fd)
            finally:
                os.close(tmp_fd)
            os.renameat(cur_fd, tmpname, cur_fd, leaf)
            os.fsync(cur_fd)
        finally:
            os.close(cur_fd)
    else:
        leaf = parts[0]
        tmpname = leaf + ".tmp-" + secrets.token_hex(8)
        tmp_fd = os.openat(dirfd, tmpname, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            os.write(tmp_fd, data)
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
        os.renameat(dirfd, tmpname, dirfd, leaf)
        os.fsync(dirfd)

def process_file(base_dir: str, input_rel: str, output_rel: str):
    if not _is_safe_relative(input_rel) or not _is_safe_relative(output_rel):
        raise OSError("Unsafe relative path")
    os.makedirs(base_dir, exist_ok=True)

    dirfd = _open_dirfd(base_dir)
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            in_fd = os.openat(dirfd, input_rel, flags)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise
            raise
        try:
            st = os.fstat(in_fd)
            if not stat_is_regular(st.st_mode):
                raise OSError("Not a regular file")
            if st.st_size < 0 or st.st_size > MAX_FILE_SIZE:
                raise OSError("File size invalid or exceeds limit")

            buf = bytearray()
            checksum = 0
            total = 0
            while True:
                chunk = os.read(in_fd, 65536)
                if not chunk:
                    break
                buf.extend(chunk)
                total += len(chunk)
                # checksum while reading
                for b in chunk:
                    checksum = (checksum + b) & 0xFFFFFFFF
            # Save results
            data = f"{total} {checksum}\n".encode("utf-8")
            _safe_write_file_at(dirfd, output_rel, data)
            return (total, checksum, checksum == 0)
        finally:
            os.close(in_fd)
    finally:
        os.close(dirfd)

def stat_is_regular(mode: int) -> bool:
    return (mode & 0o170000) == 0o100000

def _safe_create_input(base_dir: str, rel: str, data: bytes):
    if not _is_safe_relative(rel):
        raise OSError("Unsafe relative path")
    os.makedirs(base_dir, exist_ok=True)
    dirfd = _open_dirfd(base_dir)
    try:
        _safe_write_file_at(dirfd, rel, data)
    finally:
        os.close(dirfd)

def main():
    base = "sandbox_py"
    os.makedirs(base, exist_ok=True)

    # Prepare 5 input files
    _safe_create_input(base, "inputs/empty.bin", b"")
    _safe_create_input(base, "inputs/hello.txt", b"hello")
    _safe_create_input(base, "inputs/1kb.bin", b"A" * 1024)
    _safe_create_input(base, "inputs/seq.bin", bytes(range(256)))
    _safe_create_input(base, "inputs/zeros.txt", b"0" * 10000)

    # 5 test cases
    try:
        print("T1:", process_file(base, "inputs/empty.bin", "outputs/empty.out"))
        print("T2:", process_file(base, "inputs/hello.txt", "outputs/hello.out"))
        print("T3:", process_file(base, "inputs/1kb.bin", "outputs/1kb.out"))
        print("T4:", process_file(base, "inputs/seq.bin", "outputs/seq.out"))
        print("T5:", process_file(base, "inputs/zeros.txt", "outputs/zeros.out"))
    except Exception as e:
        print("Error:", str(e), file=sys.stderr)

if __name__ == "__main__":
    main()