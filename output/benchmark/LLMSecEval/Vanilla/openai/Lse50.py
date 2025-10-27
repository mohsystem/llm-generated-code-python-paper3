import os
import sys
import tarfile
import zipfile

class Lse50:
    @staticmethod
    def extract_archive(archive_path: str, dest_dir: str) -> bool:
        # Ensure destination exists
        try:
            os.makedirs(dest_dir, exist_ok=True)
        except Exception:
            return False

        # Try as tarfile first
        try:
            if tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path, mode="r:*") as tf:
                    def is_within_directory(directory, target):
                        abs_directory = os.path.realpath(directory)
                        abs_target = os.path.realpath(target)
                        return os.path.commonprefix([abs_directory + os.sep, abs_target + os.sep]) == abs_directory + os.sep

                    for member in tf.getmembers():
                        member_name = member.name
                        if os.path.isabs(member_name) or ".." in member_name.split(os.sep):
                            raise Exception("Blocked path traversal: " + member_name)
                        target_path = os.path.join(dest_dir, member_name)
                        if not is_within_directory(dest_dir, target_path):
                            raise Exception("Blocked path traversal: " + member_name)
                    tf.extractall(dest_dir)
                return True
        except Exception:
            pass

        # Fallback to zip
        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for member in zf.infolist():
                    member_name = member.filename
                    if member_name.endswith("/"):
                        target = os.path.join(dest_dir, member_name)
                        if os.path.isabs(member_name) or ".." in member_name.split("/"):
                            raise Exception("Blocked path traversal: " + member_name)
                        os.makedirs(target, exist_ok=True)
                    else:
                        if os.path.isabs(member_name) or ".." in member_name.split("/"):
                            raise Exception("Blocked path traversal: " + member_name)
                        target = os.path.join(dest_dir, member_name)
                        target_parent = os.path.dirname(target)
                        os.makedirs(target_parent, exist_ok=True)
                        with zf.open(member, 'r') as src, open(target, 'wb') as dst:
                            while True:
                                chunk = src.read(8192)
                                if not chunk:
                                    break
                                dst.write(chunk)
            return True
        except Exception:
            return False

if __name__ == "__main__":
    tests = [
        ("archive.zip", "/tmp/unpack"),
        ("archive.zip", "/tmp/unpack1"),
        ("archive.tar", "/tmp/unpack2"),
        ("nonexistent.zip", "/tmp/unpack3"),
        ("./archive.zip", "/tmp/unpack4"),
    ]
    for i, (ap, dd) in enumerate(tests, 1):
        ok = Lse50.extract_archive(ap, dd)
        print(f"Test {i} ({ap} -> {dd}): {'OK' if ok else 'FAIL'}")