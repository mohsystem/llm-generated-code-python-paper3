import os
import io
import tarfile
import zipfile

# Chain-of-Through condensed steps in secure code (high-level):
# 1) Understand: Extract archive.zip (as tar if possible) into /tmp/unpack.
# 2) Security: prevent path traversal, skip links/devices, limit sizes.
# 3) Implement safe extraction for tar or zip.
# 4) Review: checks precede writes; minimal privileges.
# 5) Output: final safe functions and simple tests.

def _is_within_directory(directory: str, target: str) -> bool:
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    try:
        common = os.path.commonpath([abs_directory, abs_target])
    except Exception:
        return False
    return common == abs_directory

def _safe_write_file(stream, dest_path: str, max_file_size: int = 1024 * 1024 * 1024) -> None:
    # Copy stream to dest_path with a maximum size to mitigate archive bombs.
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    written = 0
    bufsize = 8192
    with open(dest_path, "wb") as out:
        while True:
            chunk = stream.read(bufsize)
            if not chunk:
                break
            written += len(chunk)
            if written > max_file_size:
                raise IOError(f"File too large (possible archive bomb): {dest_path}")
            out.write(chunk)

def extract_archive_as_tar(archive_path: str, dest_dir: str):
    # Attempts to open as tarfile; if not tar, falls back to zipfile.
    # Returns a list of extracted file paths (absolute).
    if not os.path.isfile(archive_path):
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    os.makedirs(dest_dir, exist_ok=True)
    extracted = []

    def _extract_tar(path, dest):
        out = []
        with tarfile.open(path, mode="r:*") as tf:
            for member in tf.getmembers():
                name = member.name or ""
                # Basic sanitization
                if name.startswith("/") or name.startswith("\\") or ".." in name:
                    continue
                # Skip links and special files
                if member.islnk() or member.issym() or member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                    continue

                target_path = os.path.normpath(os.path.join(dest, name))
                if not _is_within_directory(dest, target_path):
                    continue

                if member.isdir():
                    os.makedirs(target_path, exist_ok=True)
                elif member.isfile():
                    fobj = tf.extractfile(member)
                    if fobj is None:
                        continue
                    try:
                        _safe_write_file(fobj, target_path)
                    finally:
                        try:
                            fobj.close()
                        except Exception:
                            pass
                    out.append(os.path.abspath(target_path))
        return out

    def _extract_zip(path, dest):
        out = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                name = info.filename or ""
                if name.startswith("/") or name.startswith("\\") or ".." in name:
                    continue

                # Detect symlinks from external attributes (UNIX)
                is_symlink = False
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    is_symlink = True
                if is_symlink:
                    # Skip symlinks for safety
                    continue

                target_path = os.path.normpath(os.path.join(dest, name))
                if not _is_within_directory(dest, target_path):
                    continue

                if name.endswith("/") or name.endswith("\\") or info.is_dir():
                    os.makedirs(target_path, exist_ok=True)
                else:
                    with zf.open(info, "r") as src:
                        _safe_write_file(src, target_path)
                    out.append(os.path.abspath(target_path))
        return out

    if tarfile.is_tarfile(archive_path):
        extracted = _extract_tar(archive_path, dest_dir)
    elif zipfile.is_zipfile(archive_path):
        extracted = _extract_zip(archive_path, dest_dir)
    else:
        raise IOError("Unsupported archive format; not a tar or zip file")

    return extracted

if __name__ == "__main__":
    # 5 test cases (will only succeed if the files exist on your system)
    tests = [
        ("archive.zip", "/tmp/unpack"),          # zip fallback, per prompt
        ("archive.tar", "/tmp/unpack"),          # tar file
        ("archive.tar.gz", "/tmp/unpack"),       # compressed tar
        ("nonexistent.zip", "/tmp/unpack"),      # missing archive
        ("archive.zip", "/tmp/unpack/subdir"),   # nested dest
    ]
    for i, (ap, dd) in enumerate(tests, 1):
        try:
            result = extract_archive_as_tar(ap, dd)
            print(f"Test {i}: Extracted {len(result)} files")
        except Exception as e:
            print(f"Test {i}: Failed with error: {e}")