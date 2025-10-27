import io
import os
import tarfile
import shutil
import secrets
from typing import List, Tuple

# Secure tar extraction using context managers ("with") and open().
# - Supports .tar, .tar.gz, .tar.bz2 via tarfile with auto-detection.
# - Prevents path traversal by validating and normalizing member paths.
# - Skips symlinks and special files; extracts only regular files and directories.
# - Uses open-then-validate and atomic writes with fsync and os.replace.
# - Writes to /tmp/unpack by default with restrictive permissions.

MAX_TAR_SIZE = 200 * 1024 * 1024  # 200MB cap for tar input size
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB cap per file


def _is_regular_file_member(m: tarfile.TarInfo) -> bool:
    return m.isreg()


def _is_directory_member(m: tarfile.TarInfo) -> bool:
    return m.isdir()


def _safe_join(base: str, name: str) -> str:
    if name.startswith("/") or name.startswith("\\"):
        raise ValueError("Absolute paths are not allowed")
    # Normalize to remove ../ and ./ parts
    dest = os.path.normpath(os.path.join(base, name))
    # Ensure within base
    base_norm = os.path.normpath(base)
    if os.path.commonpath([base_norm, dest]) != base_norm:
        raise ValueError("Path escapes base directory")
    return dest


def _mkdirs_secure(path: str) -> None:
    # Create directories while rejecting existing symlinks
    path = os.path.abspath(path)
    parts = []
    while True:
        head, tail = os.path.split(path)
        parts.append((head, tail))
        if not tail:
            break
        path = head
    parts.reverse()
    current = parts[0][0]
    if not current:
        current = "/"
    for _, tail in parts[1:]:
        current = os.path.join(current, tail)
        if os.path.exists(current):
            if os.path.islink(current):
                raise OSError(f"Refuse to traverse symlink: {current}")
            if not os.path.isdir(current):
                raise OSError(f"Not a directory: {current}")
        else:
            os.mkdir(current, 0o700)


def extract_tar_secure(tar_path: str, dest_dir: str = "/tmp/unpack") -> List[str]:
    if not isinstance(tar_path, str) or not tar_path:
        raise ValueError("Invalid tar_path")
    if not isinstance(dest_dir, str) or not dest_dir:
        raise ValueError("Invalid dest_dir")

    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    extracted: List[str] = []

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags |= nofollow
    # open-then-validate
    fd = os.open(tar_path, flags)
    try:
        st = os.fstat(fd)
        if not (st.st_mode & 0o170000) == 0o100000:  # regular file
            raise OSError("Not a regular file")
        if st.st_size > MAX_TAR_SIZE:
            raise OSError("Tar too large")

        # Wrap fd in a file object without reopening by path
        with os.fdopen(fd, "rb", closefd=False) as fobj:
            # tarfile will auto-detect compression with mode r:*
            with tarfile.open(fileobj=fobj, mode="r:*") as tf:
                for m in tf.getmembers():
                    try:
                        if _is_directory_member(m):
                            dest_path = _safe_join(dest_dir, m.name)
                            _mkdirs_secure(dest_path)
                            continue
                        if not _is_regular_file_member(m):
                            # Skip symlinks and special types
                            continue
                        dest_path = _safe_join(dest_dir, m.name)
                        parent = os.path.dirname(dest_path)
                        if parent:
                            _mkdirs_secure(parent)
                        if m.size < 0 or m.size > MAX_FILE_SIZE:
                            raise OSError("File too large")
                        src = tf.extractfile(m)
                        if src is None:
                            continue
                        tmp_path = dest_path + f".tmp.{secrets.token_hex(8)}"
                        fd_out = os.open(
                            tmp_path,
                            os.O_WRONLY
                            | os.O_CREAT
                            | os.O_EXCL
                            | getattr(os, "O_NOFOLLOW", 0),
                            0o600,
                        )
                        try:
                            with os.fdopen(fd_out, "wb", closefd=False) as out:
                                remaining = m.size
                                while remaining > 0:
                                    chunk = src.read(min(65536, remaining))
                                    if not chunk:
                                        raise OSError("Unexpected EOF in member")
                                    out.write(chunk)
                                    remaining -= len(chunk)
                                out.flush()
                                os.fsync(fd_out)
                            os.replace(tmp_path, dest_path)
                            extracted.append(dest_path)
                        finally:
                            try:
                                os.close(fd_out)
                            except OSError:
                                pass
                            try:
                                os.unlink(tmp_path)
                            except FileNotFoundError:
                                pass
                    except Exception:
                        # Fail closed per entry: skip with minimal info
                        continue
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    return extracted


def _create_test_tar(archive_path: str, entries: List[Tuple[str, bytes]], mode: str = "w") -> None:
    # mode: 'w', 'w:gz', 'w:bz2'
    with tarfile.open(archive_path, mode) as tf:
        for name, data in entries:
            if name.endswith("/"):
                ti = tarfile.TarInfo(name=name)
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif isinstance(data, bytes):
                ti = tarfile.TarInfo(name=name)
                ti.size = len(data)
                ti.mode = 0o644
                tf.addfile(ti, fileobj=io.BytesIO(data))
            else:
                # symlink example: data is the link target
                ti = tarfile.TarInfo(name=name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = str(data)
                tf.addfile(ti)


def main():
    base = "/tmp/unpack"
    try:
        shutil.rmtree(base)
    except FileNotFoundError:
        pass
    os.makedirs(base, mode=0o700, exist_ok=True)

    # Test 1: plain tar with files and directory
    t1 = "/tmp/test1.tar"
    _create_test_tar(
        t1,
        [
            ("a.txt", b"hello python tar"),
            ("sub/", b""),
            ("sub/c.txt", b"nested"),
        ],
        mode="w",
    )
    print("Test1:", extract_tar_secure(t1, os.path.join(base, "t1")))

    # Test 2: gz tar
    t2 = "/tmp/test2.tar.gz"
    _create_test_tar(
        t2,
        [
            ("g.txt", b"gzip content"),
            ("dir/", b""),
            ("dir/h.txt", b"more gzip"),
        ],
        mode="w:gz",
    )
    print("Test2:", extract_tar_secure(t2, os.path.join(base, "t2")))

    # Test 3: bz2 tar
    t3 = "/tmp/test3.tar.bz2"
    _create_test_tar(
        t3,
        [
            ("b.txt", b"bz2 content"),
            ("d/", b""),
            ("d/e.txt", b"more bz2"),
        ],
        mode="w:bz2",
    )
    print("Test3:", extract_tar_secure(t3, os.path.join(base, "t3")))

    # Test 4: traversal attempt (should be rejected/skipped)
    t4 = "/tmp/test4.tar"
    _create_test_tar(
        t4,
        [
            ("../evil.txt", b"nope"),
            ("safe.txt", b"ok"),
        ],
        mode="w",
    )
    print("Test4:", extract_tar_secure(t4, os.path.join(base, "t4")))

    # Test 5: symlink entry should be skipped
    t5 = "/tmp/test5.tar"
    _create_test_tar(
        t5,
        [
            ("link-to-a", "a.txt"),  # symlink
            ("ok.txt", b"present"),
        ],
        mode="w",
    )
    print("Test5:", extract_tar_secure(t5, os.path.join(base, "t5")))

    # Demonstrate with open() reading a file
    demo_dir = os.path.join(base, "demo")
    os.makedirs(demo_dir, mode=0o700, exist_ok=True)
    demo_file = os.path.join(demo_dir, "demo.txt")
    with open(demo_file, "wb") as f:
        f.write(b"with-statement demo\n")
        f.flush()
        os.fsync(f.fileno())
    with open(demo_file, "rb") as f:
        data = f.read()
        print("Demo file bytes:", len(data))


if __name__ == "__main__":
    main()