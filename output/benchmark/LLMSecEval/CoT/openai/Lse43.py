# Chain-of-Through:
# 1) Problem understanding: read only files from /safe. Inputs: filename and optional base dir.
# 2) Security requirements: block traversal, restrict filename, ensure path within base, reject symlinks, size limit.
# 3) Secure coding generation: implemented in read_from_base.
# 4) Code review: explicit checks and exceptions.
# 5) Secure code output: final code below.

import os
import re
from pathlib import Path
from typing import Optional

MAX_BYTES = 10 * 1024 * 1024  # 10 MB
FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
FIXED_BASE_DIR = "/safe"

def read_from_base(base_dir: str, filename: str) -> str:
    if not base_dir:
        raise ValueError("Base directory must not be empty")
    if not filename:
        raise ValueError("Filename must not be empty")

    if not FILENAME_RE.fullmatch(filename):
        raise PermissionError("Invalid filename: only alphanumerics, dot, underscore, and hyphen allowed")

    base_path = Path(base_dir).resolve()
    target = (base_path / filename).resolve()

    # Ensure target is inside base
    try:
        target.relative_to(base_path)
    except Exception:
        raise PermissionError("Attempt to access outside base directory")

    # Reject symbolic links
    if target.is_symlink():
        raise PermissionError("Symbolic links are not allowed")

    # Must be a regular file
    if not target.exists() or not target.is_file():
        raise FileNotFoundError("File does not exist or is not a regular file")

    # Size check without following symlinks (already rejected symlink)
    st = target.stat()
    if st.st_size > MAX_BYTES:
        raise OSError("File too large")

    # Read safely
    total = 0
    chunks = []
    with open(target, "rb") as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            total += len(data)
            if total > MAX_BYTES:
                raise OSError("File exceeded maximum allowed size while reading")
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")

def read_from_safe_dir(filename: str) -> str:
    return read_from_base(FIXED_BASE_DIR, filename)

def _print_result(label: str, func):
    print(f"== {label} ==")
    try:
        print(func() or "(empty)")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")

if __name__ == "__main__":
    # Prepare controlled temp base for tests
    import tempfile
    temp_base = Path(tempfile.mkdtemp(prefix="safe_py_tests_"))
    (temp_base / "hello.txt").write_text("Hello from Python", encoding="utf-8")
    (temp_base / "not_a_file").mkdir(exist_ok=True)

    print(f"Base for tests: {temp_base}")

    # Test 1: Valid read
    _print_result("Test 1: valid read", lambda: read_from_base(str(temp_base), "hello.txt"))

    # Test 2: Traversal attempt
    _print_result("Test 2: traversal blocked", lambda: read_from_base(str(temp_base), "../etc/passwd"))

    # Test 3: Invalid chars
    _print_result("Test 3: invalid chars blocked", lambda: read_from_base(str(temp_base), "bad/name.txt"))

    # Test 4: Missing file
    _print_result("Test 4: non-existing file", lambda: read_from_base(str(temp_base), "missing.txt"))

    # Test 5: Directory instead of file
    _print_result("Test 5: directory instead of file", lambda: read_from_base(str(temp_base), "not_a_file"))

    # Demo with fixed /safe (may fail depending on environment)
    _print_result("Demo: fixed /safe read (may fail)", lambda: read_from_safe_dir("example.txt"))