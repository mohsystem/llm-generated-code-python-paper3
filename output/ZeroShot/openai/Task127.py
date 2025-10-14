import os
import shutil
import tempfile
from typing import Optional

class Task127:
    @staticmethod
    def safe_copy_to_temp(base_dir: str, relative_path: str, temp_dir: Optional[str] = None) -> Optional[str]:
        if base_dir is None or relative_path is None:
            print("Invalid arguments: base_dir and relative_path must not be None.", file=os.sys.stderr)
            return None
        try:
            if not os.path.isdir(base_dir):
                print("Base directory does not exist or is not a directory.", file=os.sys.stderr)
                return None

            base_real = os.path.realpath(base_dir)
            candidate_joined = os.path.normpath(os.path.join(base_real, relative_path))
            candidate_real = os.path.realpath(candidate_joined)

            # Ensure candidate is within base directory
            if not (candidate_real == base_real or candidate_real.startswith(base_real + os.sep)):
                print("Security violation: Attempted path traversal outside base directory.", file=os.sys.stderr)
                return None

            if not os.path.isfile(candidate_real) or not os.access(candidate_real, os.R_OK):
                print("Source is not a regular readable file.", file=os.sys.stderr)
                return None

            temp_base = temp_dir if temp_dir else tempfile.gettempdir()
            os.makedirs(temp_base, exist_ok=True)

            fd, temp_path = tempfile.mkstemp(prefix="safe_copy_", suffix=".tmp", dir=temp_base)
            try:
                os.chmod(temp_path, 0o600)
            except PermissionError:
                pass  # Windows or restricted FS may not support chmod as expected

            with os.fdopen(fd, "wb") as out_f, open(candidate_real, "rb") as in_f:
                shutil.copyfileobj(in_f, out_f, length=1024 * 1024)

            return temp_path
        except Exception as e:
            print(f"Error: {e}", file=os.sys.stderr)
            return None

if __name__ == "__main__":
    # Prepare test environment
    base_root = tempfile.mkdtemp(prefix="task127_py_base_")
    a_path = os.path.join(base_root, "a.txt")
    sub_dir = os.path.join(base_root, "sub")
    b_path = os.path.join(sub_dir, "b.txt")
    os.makedirs(sub_dir, exist_ok=True)
    with open(a_path, "w", encoding="utf-8") as f:
        f.write("Hello A")
    with open(b_path, "w", encoding="utf-8") as f:
        f.write("Hello B")

    # 5 Test cases
    r1 = Task127.safe_copy_to_temp(base_root, "a.txt")
    print(f"Test1: {r1}")

    r2 = Task127.safe_copy_to_temp(base_root, "sub/b.txt")
    print(f"Test2: {r2}")

    r3 = Task127.safe_copy_to_temp(base_root, "../../etc/passwd")
    print(f"Test3: {r3}")

    r4 = Task127.safe_copy_to_temp(base_root, "missing.txt")
    print(f"Test4: {r4}")

    r5 = Task127.safe_copy_to_temp(a_path, "a.txt")  # base_dir is a file, not a directory
    print(f"Test5: {r5}")