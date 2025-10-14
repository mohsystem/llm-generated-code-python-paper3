import os
import sys
import stat
import tarfile
import zipfile
from typing import List

def _is_within_directory(base: str, target: str) -> bool:
    base_abs = os.path.abspath(base)
    target_abs = os.path.abspath(target)
    try:
        common = os.path.commonpath([base_abs, target_abs])
    except ValueError:
        return False
    return common == base_abs

def extract_archive(archive_path: str, dest_dir: str) -> List[str]:
    if not isinstance(archive_path, str) or not isinstance(dest_dir, str):
        raise TypeError("Paths must be strings")
    os.makedirs(dest_dir, exist_ok=True)
    lower = archive_path.lower()
    if lower.endswith(".zip"):
        return _extract_zip(archive_path, dest_dir)
    elif lower.endswith(".tar") or lower.endswith(".tar.gz") or lower.endswith(".tgz") or lower.endswith(".tar.bz2") or lower.endswith(".tbz2") or lower.endswith(".tar.xz") or lower.endswith(".txz"):
        return _extract_tar(archive_path, dest_dir)
    else:
        raise ValueError(f"Unsupported archive type: {archive_path}")

def _extract_zip(zip_path: str, dest_dir: str) -> List[str]:
    extracted = []
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                continue
            target_path = os.path.join(dest_dir, name)
            if not _is_within_directory(dest_dir, target_path):
                continue
            if name.endswith("/"):
                os.makedirs(target_path, exist_ok=True)
                continue
            parent = os.path.dirname(target_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            # Avoid setting executable bits blindly; write file content safely
            with zf.open(info, 'r') as src, open(target_path, 'wb') as dst:
                while True:
                    chunk = src.read(8192)
                    if not chunk:
                        break
                    dst.write(chunk)
            extracted.append(os.path.abspath(target_path))
    return extracted

def _extract_tar(tar_path: str, dest_dir: str) -> List[str]:
    extracted = []
    # Use tarfile with manual safe checks
    mode = 'r:*' if any(tar_path.lower().endswith(ext) for ext in [".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"]) else 'r:'
    with tarfile.open(tar_path, mode) as tf:
        for member in tf.getmembers():
            name = member.name.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                continue
            target_path = os.path.join(dest_dir, name)
            if not _is_within_directory(dest_dir, target_path):
                continue
            if member.isdir():
                os.makedirs(target_path, exist_ok=True)
                continue
            if member.issym() or member.islnk():
                # Skip links for safety
                continue
            parent = os.path.dirname(target_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            f = tf.extractfile(member)
            if f is None:
                continue
            with f, open(target_path, 'wb') as dst:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    dst.write(chunk)
            # Optionally set permissions (mask to safe bits)
            try:
                os.chmod(target_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
            except Exception:
                pass
            extracted.append(os.path.abspath(target_path))
    return extracted

def main():
    # 5 test cases (paths created as needed)
    import tempfile
    base = tempfile.mkdtemp(prefix="task117_py_")
    out1 = os.path.join(base, "out1")
    out2 = os.path.join(base, "out2")
    out3 = os.path.join(base, "out3")
    out4 = os.path.join(base, "out4")
    out5 = os.path.join(base, "out5")

    # Create sample ZIP with traversal attempt
    zip1 = os.path.join(base, "t1.zip")
    with zipfile.ZipFile(zip1, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", "hello zip\n")
        z.writestr("sub/b.txt", "world\n")
        z.writestr("../evil.txt", "nope\n")

    # Create sample TAR (uncompressed) with traversal attempt
    tar1 = os.path.join(base, "t1.tar")
    with tarfile.open(tar1, "w") as t:
        info = tarfile.TarInfo("x.txt")
        data = b"hello tar\n"
        info.size = len(data)
        t.addfile(info, fileobj=os.BytesIO(data) if hasattr(os, "BytesIO") else None)
        # Workaround for older Python: emulate BytesIO with tempfile
        if not hasattr(os, "BytesIO"):
            import io
            t.members[-1] = t.members[-1]  # no-op to avoid linter
        info2 = tarfile.TarInfo("dir/y.txt")
        data2 = b"nested\n"
        info2.size = len(data2)
        t.addfile(info2, fileobj=__import__('io').BytesIO(data2))
        # traversal
        info3 = tarfile.TarInfo("../escape.txt")
        data3 = b"bad"
        info3.size = len(data3)
        t.addfile(info3, fileobj=__import__('io').BytesIO(data3))

    try:
        print("Test1 ZIP safe:", extract_archive(zip1, out1))
    except Exception as e:
        print("Test1 failed:", e)

    try:
        print("Test2 ZIP traversal filtered:", extract_archive(zip1, out2))
    except Exception as e:
        print("Test2 failed:", e)

    try:
        print("Test3 TAR safe:", extract_archive(tar1, out3))
    except Exception as e:
        print("Test3 failed:", e)

    try:
        print("Test4 TAR traversal filtered:", extract_archive(tar1, out4))
    except Exception as e:
        print("Test4 failed:", e)

    try:
        print("Test5 unsupported:", extract_archive(os.path.join(base, "file.rar"), out5))
    except Exception as e:
        print("Test5 expected failure:", e)

if __name__ == "__main__":
    main()