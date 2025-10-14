import os
import sys
import tempfile
import shutil
from typing import Tuple

# Return codes:
# 0 = success
# 1 = invalid input
# 2 = target path resolves outside base
# 3 = file not found
# 4 = not a regular file
# 5 = is a symlink
# 6 = delete failed
def secure_delete(base_dir: str, user_path: str) -> int:
    try:
        if not isinstance(base_dir, str) or not isinstance(user_path, str):
            return 1
        if not base_dir or not user_path:
            return 1
        if len(user_path) > 4096:
            return 1
        # Reject absolute
        if os.path.isabs(user_path):
            return 1
        # Reject control chars
        if any(ord(ch) < 32 for ch in user_path):
            return 1
        # Reject path components with ..
        parts = [p for p in user_path.replace("\\", "/").split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            return 1

        base_real = os.path.realpath(base_dir)
        candidate = os.path.normpath(os.path.join(base_real, *parts))
        # Ensure candidate within base
        try:
            common = os.path.commonpath([base_real, candidate])
        except ValueError:
            return 2
        if common != base_real:
            return 2

        # Existence check without following symlinks: use lstat
        try:
            st = os.lstat(candidate)
        except FileNotFoundError:
            return 3
        # Refuse if symlink
        if hasattr(st, "st_mode") and stat.S_ISLNK(st.st_mode):
            return 5
        # Must be regular file
        if not stat_is_regular(st.st_mode):
            return 4

        # Attempt unlink using dir_fd to reduce TOCTOU (POSIX)
        parent = os.path.dirname(candidate) or base_real
        name = os.path.basename(candidate)
        try:
            if hasattr(os, "open") and hasattr(os, "unlink"):
                flags = getattr(os, "O_RDONLY", 0)
                if hasattr(os, "O_DIRECTORY"):
                    flags |= os.O_DIRECTORY
                dirfd = os.open(parent, flags)
                try:
                    # Re-validate using fstatat-like behavior via lstat on parent/name (best-effort)
                    # Python doesn't expose fstatat with AT_SYMLINK_NOFOLLOW directly; rely on earlier lstat and immediate unlink
                    os.unlink(name, dir_fd=dirfd)
                finally:
                    os.close(dirfd)
            else:
                os.unlink(candidate)
        except PermissionError:
            return 6
        except FileNotFoundError:
            return 3
        except NotImplementedError:
            # Fallback if dir_fd unsupported
            try:
                os.unlink(candidate)
            except Exception:
                return 6
        return 0
    except Exception:
        return 6

def stat_is_symlink(mode: int) -> bool:
    # S_IFLNK = 0o120000
    return (mode & 0o170000) == 0o120000

def stat_is_regular(mode: int) -> bool:
    # S_IFREG = 0o100000
    return (mode & 0o170000) == 0o100000

def run_tests():
    base = tempfile.mkdtemp(prefix="safe-del-py-")
    try:
        f1 = os.path.join(base, "file1.txt")
        sub = os.path.join(base, "sub")
        nested = os.path.join(sub, "inside.txt")
        f2 = os.path.join(base, "file2.txt")
        os.makedirs(sub, exist_ok=True)
        with open(f1, "w", encoding="utf-8") as fp:
            fp.write("one")
        with open(nested, "w", encoding="utf-8") as fp:
            fp.write("two")
        with open(f2, "w", encoding="utf-8") as fp:
            fp.write("three")
        sym = os.path.join(base, "link_to_file2")
        try:
            os.symlink("file2.txt", sym)
        except (OSError, NotImplementedError):
            pass

        tests = [
            (base, "file1.txt"),       # success
            (base, "sub/inside.txt"),  # success
            (base, "sub"),             # reject: directory
            (base, "link_to_file2"),   # reject: symlink (if created) else not found
            (base, "../outside.txt"),  # reject: traversal
        ]
        for i, (bd, up) in enumerate(tests, 1):
            rc = secure_delete(bd, up)
            print(f"Test {i} => {rc}")
    finally:
        # Clean up base directory recursively
        shutil.rmtree(base, ignore_errors=True)

if __name__ == "__main__":
    # Run internal tests
    run_tests()
    # If CLI args provided: expect baseDir and userPath
    if len(sys.argv) >= 3:
        code = secure_delete(sys.argv[1], sys.argv[2])
        print(code)