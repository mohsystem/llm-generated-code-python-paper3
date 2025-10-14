import os
import sys
import tempfile
import string

def read_file(filename: str) -> str:
    if filename is None or str(filename).strip() == "":
        return "ERROR: Filename is empty."

    if not _is_valid_filename(filename):
        return "ERROR: Filename contains invalid characters."

    try:
        if not os.path.exists(filename):
            return "ERROR: File does not exist."
        if os.path.isdir(filename):
            return "ERROR: Path is a directory, not a file."
        if not os.access(filename, os.R_OK):
            return "ERROR: File is not readable."
        with open(filename, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        return f"ERROR: OS error: {e}"
    except Exception as e:
        return f"ERROR: Unexpected error: {e}"

def _is_valid_filename(name: str) -> bool:
    invalid = set('<>"|?*')
    # Disallow control chars
    for ch in name:
        if ord(ch) < 32:
            return False
        if ch in invalid:
            return False
    # Basic component length check
    sep = [os.sep]
    if os.altsep:
        sep.append(os.altsep)
    parts = [name]
    for s in sep:
        parts = sum((p.split(s) for p in parts), [])
    return all(len(p) <= 255 for p in parts if p)

if __name__ == "__main__":
    # CLI argument test
    if len(sys.argv) > 1:
        print("CLI arg result:")
        print(read_file(sys.argv[1]))

    # Create 5 test cases
    tests = []

    # 1) Valid temp file
    f1 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", prefix="task65_")
    f1.write(b"Hello from Task65 test case 1.\nLine 2.")
    f1.close()
    tests.append(f1.name)

    # 2) Valid temp file with larger content
    f2 = tempfile.NamedTemporaryFile(delete=False, suffix=".log", prefix="task65_")
    content = "".join(f"Line {i+1}: Sample content\n" for i in range(100))
    f2.write(content.encode("utf-8"))
    f2.close()
    tests.append(f2.name)

    # 3) Non-existent file
    tests.append("this_file_should_not_exist_1234567890.txt")

    # 4) Empty filename
    tests.append("")

    # 5) Invalid filename
    tests.append("bad|name.txt")

    for i, fn in enumerate(tests, 1):
        print(f"Test {i} ({fn}):")
        print(read_file(fn))