import os
import io
import tarfile
import zipfile
from pathlib import Path
from typing import List

class Lse49:
    @staticmethod
    def unzip_archive(archive_path: str, dest_dir: str) -> List[str]:
        extracted = []
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        # Attempt to open as tar file first (as requested), fallback to zip
        def _safe_extract_tar(tar: tarfile.TarFile, path: Path):
            for member in tar.getmembers():
                member_path = path / member.name
                member_resolved = member_path.resolve()
                if not str(member_resolved).startswith(str(path.resolve()) + os.sep) and member_resolved != path.resolve():
                    raise Exception(f"Blocked path traversal attempt in tar: {member.name}")
            tar.extractall(path=path)

        def _safe_extract_zip(zf: zipfile.ZipFile, path: Path) -> List[str]:
            out = []
            for member in zf.infolist():
                member_path = path / member.filename
                resolved = member_path.resolve()
                if not str(resolved).startswith(str(path.resolve()) + os.sep) and resolved != path.resolve():
                    raise Exception(f"Blocked path traversal attempt in zip: {member.filename}")
                if member.is_dir():
                    member_path.mkdir(parents=True, exist_ok=True)
                else:
                    member_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member, 'r') as src, open(member_path, 'wb') as dst:
                        dst.write(src.read())
                    out.append(str(member_path))
            return out

        tried_tar = False
        try:
            tried_tar = True
            with tarfile.open(archive_path, mode="r:*") as tf:
                _safe_extract_tar(tf, dest)
                # collect file paths
                for member in tf.getmembers():
                    if member.isfile():
                        extracted.append(str((dest / member.name).resolve()))
                return extracted
        except tarfile.TarError:
            # Not a tar archive, fallback to zip
            pass

        with zipfile.ZipFile(archive_path, 'r') as zf:
            extracted = _safe_extract_zip(zf, dest)

        return extracted

if __name__ == "__main__":
    archive = "archive.zip"
    dest = "/tmp/unpack"

    # Prepare sample zip
    # Recreate archive.zip with some files
    if os.path.exists(dest):
        # clean destination
        for root, dirs, files in os.walk(dest, topdown=False):
            for name in files:
                try:
                    os.remove(os.path.join(root, name))
                except Exception:
                    pass
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except Exception:
                    pass
        try:
            os.rmdir(dest)
        except Exception:
            pass

    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("file1.txt", "hello world 1\n")
        z.writestr("dir1/", "")  # directory entry
        z.writestr("dir1/file2.txt", "hello world 2\n")
        z.writestr("dir1/dir2/", "")
        z.writestr("dir1/dir2/file3.txt", "hello world 3\n")
        z.writestr("dir1/dir2/file4.txt", "hello world 4\n")
        z.writestr("dir1/file5.txt", "hello world 5\n")

    # 5 test cases
    for i in range(1, 6):
        files = Lse49.unzip_archive(archive, dest)
        print(f"Test {i} extracted files: {len(files)}")