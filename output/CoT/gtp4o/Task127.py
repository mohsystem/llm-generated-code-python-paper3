import os
import sys
import shutil
import tempfile
from pathlib import Path

# Step 1: Problem understanding and function definition
# Securely copy a file from a specified base directory to a securely created temporary file.
# Returns the path to the temp file as a string, or None on failure.
def copy_file_to_temp(base_dir: str, relative_file: str):
    # Step 2: Security requirements - validate inputs
    if base_dir is None or relative_file is None:
        print("Error: invalid parameters.", file=sys.stderr)
        return None
    try:
        base = Path(base_dir)
        if not base.exists() or not base.is_dir():
            print("Error: base directory not found or not a directory.", file=sys.stderr)
            return None
        base_real = base.resolve(strict=True)

        candidate = (base_real / relative_file)
        try:
            file_real = candidate.resolve(strict=True)
        except FileNotFoundError:
            print("Error: source file not found.", file=sys.stderr)
            return None

        # Ensure within base directory
        try:
            file_real.relative_to(base_real)
        except ValueError:
            print("Error: access outside base directory is not allowed.", file=sys.stderr)
            return None

        if not file_real.is_file():
            print("Error: specified path is not a regular file.", file=sys.stderr)
            return None

        # Step 3: Secure coding generation - create secure temp file and copy
        fd, temp_path = tempfile.mkstemp(prefix="Task127_", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
        except Exception:
            pass  # Ignore on non-POSIX
        with os.fdopen(fd, "wb") as out_f, open(file_real, "rb") as in_f:
            shutil.copyfileobj(in_f, out_f, length=8192)

        # Step 4: Code review - path validation, safe temp creation, restrictive perms
        return temp_path

    except PermissionError:
        print("Error: insufficient permissions.", file=sys.stderr)
        return None
    except OSError:
        print("Error: I/O failure occurred.", file=sys.stderr)
        return None


def _write_file(dir_path: Path, rel: str, data: bytes):
    p = dir_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    # Step 5: Secure code output - run 5 test cases
    base = Path(tempfile.mkdtemp(prefix="Task127_test_py_"))
    _write_file(base, "file1.txt", b"Hello, secure world!")
    _write_file(base, "empty.txt", b"")
    (base / "subdir").mkdir(exist_ok=True)
    _write_file(base, "subdir/nested.txt", b"Nested content")

    print("Test1:", copy_file_to_temp(str(base), "file1.txt"))
    print("Test2:", copy_file_to_temp(str(base), "missing.txt"))
    print("Test3:", copy_file_to_temp(str(base), "../file1.txt"))
    print("Test4:", copy_file_to_temp(str(base), "subdir"))
    print("Test5:", copy_file_to_temp(str(base), "empty.txt"))