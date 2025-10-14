# Chain-of-Through process:
# 1) Problem understanding: Provide a function to read file content by filename with validation,
#    and a main routine that also reads filename from command-line if provided and runs 5 tests.
# 2) Security requirements: Prevent path traversal by restricting filename format and ensuring
#    the resolved path remains within a base directory; enforce a maximum file size; handle errors.
# 3) Secure coding generation: Use regex for filename validation, realpath checks, size checks,
#    UTF-8 reads, and robust exception handling.
# 4) Code review: Verified checks for invalid names, boundary checks, existence, readability,
#    and max-size enforcement; avoids unsafe operations.
# 5) Secure code output: Final code below implements safeguards.

import os
import re
import sys
import tempfile

MAX_BYTES = 1024  # 1 KiB
SAFE_NAME = re.compile(r'^[A-Za-z0-9._-]{1,255}$')

def safe_read_file(base_dir: str, filename: str) -> str:
    if not base_dir:
        base_dir = "."
    if filename is None or not SAFE_NAME.fullmatch(filename):
        return "ERROR: Invalid filename format. Allowed: letters, digits, . _ - (1..255 chars)"
    try:
        base_real = os.path.realpath(base_dir)
        target_path = os.path.join(base_real, filename)

        if not os.path.exists(target_path):
            return "ERROR: File does not exist."
        if not os.path.isfile(target_path):
            return "ERROR: Not a regular file."
        if not os.access(target_path, os.R_OK):
            return "ERROR: File is not readable."

        # Ensure canonical path (guard against symlinks escaping base)
        target_real = os.path.realpath(target_path)
        # Check target_real starts with base_real + path separator or equals base_real
        common = os.path.commonpath([base_real, target_real])
        if common != base_real:
            return "ERROR: Unsafe path detected."

        size = os.path.getsize(target_real)
        if size > MAX_BYTES:
            return f"ERROR: File too large ({size} bytes). Max allowed: {MAX_BYTES} bytes."

        with open(target_real, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"ERROR: {str(e)}"

if __name__ == "__main__":
    base = tempfile.mkdtemp(prefix="task65_")

    # Create test files
    with open(os.path.join(base, "sample1.txt"), "w", encoding="utf-8") as f:
        f.write("Hello, Task65!")
    with open(os.path.join(base, "sample-2.txt"), "w", encoding="utf-8") as f:
        f.write("Second sample content.")
    with open(os.path.join(base, "big.txt"), "wb") as f:
        f.write(b"A" * 1500)

    tests = [
        "sample1.txt",   # valid
        "sample-2.txt",  # valid
        "../etc/passwd", # invalid format (blocked)
        "missing.txt",   # missing
        "big.txt"        # too large
    ]

    for i, t in enumerate(tests, 1):
        print(f"Test {i} ({t}):")
        print(safe_read_file(base, t))
        print("-----")

    # Command-line filename (uses current directory as base)
    if len(sys.argv) > 1:
        print("Command-line read:")
        print(safe_read_file(".", sys.argv[1]))