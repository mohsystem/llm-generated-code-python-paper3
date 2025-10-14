# Chain-of-Through process in code generation:
# 1) Problem understanding: Delete file path passed via command-line; provide a function accepting path and returning success/failure.
# 2) Security requirements: Validate input, avoid deleting directories or symlinks, do not follow symlinks, handle exceptions.
# 3) Secure coding generation: Use os.lstat to identify symlinks; ensure path refers to a regular file; delete with os.remove.
# 4) Code review: Check for empty path, invalid path, existence, directory/symlink avoidance, and exception handling.
# 5) Secure code output: Final function and main with 5 test cases if no CLI args; otherwise process CLI args.

import os
import sys
import stat
import tempfile
import uuid
import shutil

def delete_file_secure(path: str) -> bool:
    if path is None:
        return False
    p = path.strip()
    if not p:
        return False
    try:
        st = os.lstat(p)  # do not follow symlinks
    except (FileNotFoundError, OSError):
        return False

    # Reject directories and symlinks
    if stat.S_ISDIR(st.st_mode):
        return False
    if stat.S_ISLNK(st.st_mode):
        return False
    if not stat.S_ISREG(st.st_mode):
        return False

    try:
        os.remove(p)
        return True
    except Exception:
        return False

def _create_temp_file() -> str:
    fd, name = tempfile.mkstemp(prefix="Task69_", suffix=".tmp")
    os.close(fd)
    return name

def main():
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            res = delete_file_secure(a)
            print(f"{a} -> {'deleted' if res else 'failed'}")
        return

    # Five test cases
    # Test 1: Create temp file and delete (expect True)
    temp1 = _create_temp_file()
    t1 = delete_file_secure(temp1)
    print("Test1 delete temp file:", "PASS" if t1 else "FAIL")

    # Test 2: Delete same file again (expect False)
    t2 = delete_file_secure(temp1)
    print("Test2 delete non-existent file:", "PASS" if not t2 else "FAIL")

    # Test 3: Attempt to delete a directory (expect False)
    temp_dir = tempfile.mkdtemp(prefix="Task69_dir_")
    t3 = delete_file_secure(temp_dir)
    print("Test3 delete directory:", "PASS" if not t3 else "FAIL")

    # Test 4: Empty path (expect False)
    t4 = delete_file_secure("   ")
    print("Test4 empty path:", "PASS" if not t4 else "FAIL")

    # Test 5: Create another temp file and delete (expect True)
    temp2 = _create_temp_file()
    t5 = delete_file_secure(temp2)
    print("Test5 second temp file:", "PASS" if t5 else "FAIL")

    # Cleanup
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass

if __name__ == "__main__":
    main()