import os
from pathlib import Path

def read_file_from_safe_dir(safe_dir: str, requested: str) -> str:
    if safe_dir is None or requested is None:
        raise ValueError("Null parameter")
    if '\x00' in requested:
        raise ValueError("Invalid character in requested path")

    base = Path(safe_dir).resolve()
    req = Path(requested)

    if req.is_absolute():
        raise PermissionError("Absolute paths are not allowed")

    target = (base / req).resolve(strict=True)

    try:
        target.relative_to(base)
    except ValueError:
        raise PermissionError("Path traversal attempt detected")

    if not target.is_file():
        raise FileNotFoundError("Target is not a regular file")

    # Reject symlinks explicitly
    if target.is_symlink():
        raise PermissionError("Symlinks are not allowed")

    return target.read_text(encoding="utf-8")

if __name__ == "__main__":
    base = Path("safe_dir_py").resolve()
    (base / "sub").mkdir(parents=True, exist_ok=True)
    (base / "file1.txt").write_text("Hello from Python file1", encoding="utf-8")
    (base / "sub" / "inner.txt").write_text("Inner Python file", encoding="utf-8")
    outside = base.parent / "outside_py.txt"
    outside.write_text("Outside Python file", encoding="utf-8")

    safe_dir = str(base)

    # Test 1: normal file
    try:
        s1 = read_file_from_safe_dir(safe_dir, "file1.txt")
        print("Test1 OK:", s1)
    except Exception as e:
        print("Test1 ERROR:", e)

    # Test 2: subdirectory file
    try:
        s2 = read_file_from_safe_dir(safe_dir, "sub/inner.txt")
        print("Test2 OK:", s2)
    except Exception as e:
        print("Test2 ERROR:", e)

    # Test 3: traversal attempt
    try:
        s3 = read_file_from_safe_dir(safe_dir, "../outside_py.txt")
        print("Test3 OK (unexpected):", s3)
    except Exception as e:
        print("Test3 Expected ERROR:", e)

    # Test 4: absolute path attempt
    try:
        s4 = read_file_from_safe_dir(safe_dir, str(base / "file1.txt"))
        print("Test4 OK (unexpected):", s4)
    except Exception as e:
        print("Test4 Expected ERROR:", e)

    # Test 5: missing file
    try:
        s5 = read_file_from_safe_dir(safe_dir, "missing.txt")
        print("Test5 OK (unexpected):", s5)
    except Exception as e:
        print("Test5 Expected ERROR:", e)