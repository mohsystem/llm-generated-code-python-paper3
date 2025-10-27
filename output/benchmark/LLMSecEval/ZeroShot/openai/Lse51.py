import io
import os
import re
import shutil
import tarfile
from pathlib import PurePosixPath

# Securely write text to a file with restrictive permissions. Returns absolute path string.
def write_text_secure(path: str, data: str) -> str:
    if not isinstance(path, str):
        raise ValueError("path must be string")
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except Exception:
            pass
    # Use low-level os.open to specify permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(data)
    finally:
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    return os.path.abspath(path)

# Securely read text from a file. Returns content.
def read_text_secure(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# Helper to determine if a tar member path is safe
def _is_member_path_safe(member_name: str) -> bool:
    if not member_name:
        return False
    # Disallow absolute paths and Windows drive letters
    if member_name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", member_name):
        return False
    # Normalize posix-style path and reject traversal
    parts = list(PurePosixPath(member_name).parts)
    if any(p == ".." for p in parts):
        return False
    return True

# Ensure the target path stays within dest_dir
def _safe_join(dest_dir: str, member_name: str) -> str:
    candidate = os.path.normpath(os.path.join(dest_dir, member_name))
    dest_real = os.path.realpath(dest_dir)
    cand_real = os.path.realpath(candidate)
    if os.path.commonpath([dest_real, cand_real]) != dest_real:
        raise ValueError("Path traversal detected")
    return candidate

# Secure extraction that avoids directory traversal, absolute paths, and symlinks/hardlinks.
# Returns a list of extracted file paths.
def safe_extract_tar(tar_path: str, dest_dir: str = "/tmp/unpack") -> list:
    if not isinstance(tar_path, str):
        raise ValueError("tar_path must be string")
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(dest_dir, 0o700)
    except Exception:
        pass

    extracted = []
    # with-statement for context manager usage as requested
    with tarfile.open(tar_path, mode="r:*") as tf:
        for member in tf.getmembers():
            name = member.name
            if not _is_member_path_safe(name):
                continue
            # Skip symlinks and hardlinks for safety
            if member.issym() or member.islnk():
                continue

            target_path = _safe_join(dest_dir, name)

            if member.isdir():
                os.makedirs(target_path, mode=0o700, exist_ok=True)
                try:
                    os.chmod(target_path, 0o700)
                except Exception:
                    pass
            elif member.isfile():
                parent = os.path.dirname(target_path)
                if parent:
                    os.makedirs(parent, mode=0o700, exist_ok=True)
                # Extract file content securely
                src = tf.extractfile(member)
                if src is None:
                    continue
                # Write file with restricted permissions
                flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                mode = 0o600
                fd = os.open(target_path, flags, mode)
                try:
                    with os.fdopen(fd, "wb") as out_f:
                        with src:
                            shutil.copyfileobj(src, out_f)
                    try:
                        os.chmod(target_path, 0o600)
                    except Exception:
                        pass
                finally:
                    # fdopen closes fd, but in case of exception before fdopen, ensure close
                    try:
                        os.close(fd)
                    except Exception:
                        pass
                extracted.append(os.path.realpath(target_path))
            else:
                # Skip other types (fifo, device, etc.)
                continue
    return extracted

def _clean_directory_contents(directory: str) -> None:
    if not os.path.isdir(directory):
        return
    for entry in os.listdir(directory):
        full = os.path.join(directory, entry)
        try:
            if os.path.isdir(full) and not os.path.islink(full):
                shutil.rmtree(full)
            else:
                os.unlink(full)
        except Exception:
            pass

def _create_tar_with_entries(tar_path: str, entries: list, mode: str = "w") -> None:
    # entries: list of dicts: {"name": str, "data": bytes|None, "type": "file"|"dir"|"symlink", "linkname": str|None}
    with tarfile.open(tar_path, mode=mode) as tf:
        for e in entries:
            name = e["name"]
            etype = e.get("type", "file")
            if etype == "dir":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o700
                tf.addfile(ti)
            elif etype == "symlink":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = e.get("linkname", "")
                ti.mode = 0o777
                tf.addfile(ti)
            else:
                data = e.get("data", b"")
                bio = io.BytesIO(data)
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                ti.mode = 0o600
                tf.addfile(ti, fileobj=bio)

def main():
    base_tmp = "/tmp/py_lse51"
    os.makedirs(base_tmp, exist_ok=True)
    try:
        os.chmod(base_tmp, 0o700)
    except Exception:
        pass

    dest = "/tmp/unpack"
    os.makedirs(dest, exist_ok=True)

    # Test 1: Create and extract plain tar with safe files
    _clean_directory_contents(dest)
    t1 = os.path.join(base_tmp, "t1.tar")
    _create_tar_with_entries(
        t1,
        [
            {"name": "a.txt", "data": b"alpha"},
            {"name": "sub/b.txt", "data": b"bravo"},
            {"name": "sub/dir", "type": "dir"},
        ],
        mode="w",
    )
    ex1 = safe_extract_tar(t1, dest)
    print("T1 extracted:", len(ex1), "files")

    # Test 2: tar.gz extraction
    _clean_directory_contents(dest)
    t2 = os.path.join(base_tmp, "t2.tar.gz")
    _create_tar_with_entries(
        t2,
        [
            {"name": "g1.txt", "data": b"gzip one"},
            {"name": "gdir", "type": "dir"},
            {"name": "gdir/g2.txt", "data": b"gzip two"},
        ],
        mode="w:gz",
    )
    ex2 = safe_extract_tar(t2, dest)
    print("T2 extracted:", len(ex2), "files")

    # Test 3: tar.bz2 extraction
    _clean_directory_contents(dest)
    t3 = os.path.join(base_tmp, "t3.tar.bz2")
    _create_tar_with_entries(
        t3,
        [
            {"name": "b1.txt", "data": b"bz2 one"},
            {"name": "bdir/b2.txt", "data": b"bz2 two"},
        ],
        mode="w:bz2",
    )
    ex3 = safe_extract_tar(t3, dest)
    print("T3 extracted:", len(ex3), "files")

    # Test 4: traversal attempts should be skipped
    _clean_directory_contents(dest)
    t4 = os.path.join(base_tmp, "t4.tar")
    _create_tar_with_entries(
        t4,
        [
            {"name": "../evil.txt", "data": b"nope"},
            {"name": "ok/../bad.txt", "data": b"nope2"},
            {"name": "/abs/path.txt", "data": b"nope3"},
            {"name": "safe/ok.txt", "data": b"ok"},
        ],
        mode="w",
    )
    ex4 = safe_extract_tar(t4, dest)
    print("T4 extracted:", len(ex4), "files")

    # Test 5: symlink should be skipped
    _clean_directory_contents(dest)
    t5 = os.path.join(base_tmp, "t5.tar")
    _create_tar_with_entries(
        t5,
        [
            {"name": "safe.txt", "data": b"content"},
            {"name": "link-out", "type": "symlink", "linkname": "../../etc/passwd"},
        ],
        mode="w",
    )
    ex5 = safe_extract_tar(t5, dest)
    print("T5 extracted:", len(ex5), "files")

    # Demonstrate open() with with-statement for reading/writing
    p = os.path.join(base_tmp, "note.txt")
    write_text_secure(p, "This is a secure note.")
    with open(p, "r", encoding="utf-8") as fh:
        print("Note:", fh.read())

if __name__ == "__main__":
    main()