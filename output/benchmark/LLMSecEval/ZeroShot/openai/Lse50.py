import os
import tarfile
import errno
import secrets

def _is_within_directory(directory: str, target: str) -> bool:
    directory = os.path.realpath(directory)
    target = os.path.realpath(target)
    return target == directory or target.startswith(directory + os.sep)

def _ensure_dir_secure(base_dir: str, full_path: str) -> None:
    base_dir = os.path.realpath(base_dir)
    full_path = os.path.realpath(full_path)
    if not _is_within_directory(base_dir, full_path):
        raise ValueError("Path traversal detected")
    rel = os.path.relpath(full_path, base_dir)
    parts = [] if rel == os.curdir else rel.split(os.sep)
    current = base_dir
    for p in parts:
        current = os.path.join(current, p)
        # Use lstat to detect symlinks
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            # Parent components will be created as real directories
            continue
        if os.path.islink(current):
            raise ValueError("Symlink in path components is not allowed")

def extract_tar(archive_path: str, dest_dir: str):
    """
    Securely extract a tar archive to dest_dir, preventing path traversal
    and skipping symlinks. Returns a list of extracted file paths.
    """
    if not isinstance(archive_path, str) or not isinstance(dest_dir, str):
        raise TypeError("archive_path and dest_dir must be strings")

    # Create destination directory securely
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    base_real = os.path.realpath(dest_dir)

    if not os.path.isfile(archive_path):
        raise FileNotFoundError(errno.ENOENT, "Archive file not found", archive_path)

    extracted = []

    # Open as tarfile, regardless of extension, using transparent compression
    try:
        with tarfile.open(archive_path, mode="r:*") as tf:
            for member in tf.getmembers():
                # Normalize member name
                name = member.name

                # Skip invalid names
                if name is None or name.strip() == "":
                    continue

                # Tar should always use '/', but normalize anyway
                # Remove leading slashes and redundant prefixes
                while name.startswith("/") or name.startswith("./") or name.startswith(".\\") or name.startswith("\\"):
                    name = name[1:]
                # Eliminate Windows-style separators just in case
                name = name.replace("\\", "/")

                # Disallow absolute or parent traversals
                target_path = os.path.join(base_real, name)
                if not _is_within_directory(base_real, target_path):
                    raise ValueError(f"Unsafe path detected in archive entry: {member.name}")

                # Skip special files: symlinks, hardlinks, devices, fifos
                if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                    continue

                if member.isdir():
                    _ensure_dir_secure(base_real, target_path)
                    os.makedirs(target_path, mode=0o755, exist_ok=True)
                    extracted.append(target_path)
                elif member.isreg():
                    # Enforce a reasonable per-file size limit (e.g., 512MB) to mitigate DoS
                    max_file_size = 512 * 1024 * 1024
                    if member.size < 0 or member.size > max_file_size:
                        raise ValueError(f"Refusing to extract large file: {member.name} ({member.size} bytes)")

                    parent_dir = os.path.dirname(target_path)
                    os.makedirs(parent_dir, mode=0o755, exist_ok=True)
                    _ensure_dir_secure(base_real, parent_dir)
                    _ensure_dir_secure(base_real, target_path)

                    src = tf.extractfile(member)
                    if src is None:
                        # Could be a special case; skip safely
                        continue

                    tmp_path = f"{target_path}.tmp.{secrets.token_hex(8)}"
                    fd = None
                    try:
                        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        remaining = member.size
                        while True:
                            chunk = src.read(1024 * 1024)
                            if not chunk:
                                break
                            remaining -= len(chunk)
                            if remaining < -1:
                                # Safety fallback
                                raise ValueError("File size exceeded expected length")
                            os.write(fd, chunk)
                        os.fsync(fd)
                    finally:
                        if fd is not None:
                            os.close(fd)
                        src.close()

                    # Atomic replace into final destination
                    os.replace(tmp_path, target_path)
                    # Sanitize permissions
                    os.chmod(target_path, 0o644)
                    extracted.append(target_path)
                else:
                    # Unknown type; skip
                    continue
    except tarfile.ReadError as e:
        raise ValueError(f"Failed to open as a tar archive: {archive_path}") from e

    return extracted

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ("archive.zip", "/tmp/unpack"),         # 1. Extract to /tmp/unpack
        ("archive.zip", "/tmp/unpack2"),        # 2. Extract to /tmp/unpack2
        ("nonexistent.tar", "/tmp/unpack3"),    # 3. Non-existent archive
        ("archive.zip", "/tmp/unpack"),         # 4. Re-extract to same dir (idempotent)
        ("archive.zip", "/tmp/unpack4"),        # 5. Extract to another dir
    ]
    for i, (arc, dst) in enumerate(tests, 1):
        try:
            result = extract_tar(arc, dst)
            print(f"Test {i}: Extracted {len(result)} entries to {dst}")
        except Exception as ex:
            print(f"Test {i}: Failed with error: {ex}")