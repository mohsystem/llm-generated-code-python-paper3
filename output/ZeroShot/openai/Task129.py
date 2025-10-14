import os
import re
import tempfile
import shutil

MAX_FILE_SIZE = 1_048_576  # 1 MB
SAFE_NAME = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')
ALLOWED_EXTS = {'txt', 'json', 'csv'}

def fetch_file(base_dir: str, filename: str) -> str:
    if base_dir is None or filename is None:
        raise ValueError("Invalid arguments")
    if not _is_valid_filename(filename):
        raise PermissionError("Invalid filename")

    base_real = os.path.realpath(base_dir)
    target = os.path.join(base_real, filename)
    target_real = os.path.realpath(target)

    if not target_real.startswith(base_real + os.sep):
        raise PermissionError("Access denied")
    if not os.path.isfile(target_real):
        raise FileNotFoundError("File not found")

    size = os.path.getsize(target_real)
    if size > MAX_FILE_SIZE:
        raise IOError("File too large")

    with open(target_real, 'rb') as f:
        data = f.read()
    return data.decode('utf-8', errors='replace')

def _is_valid_filename(name: str) -> bool:
    if not SAFE_NAME.match(name):
        return False
    if name.startswith('.'):
        return False
    base, ext = os.path.splitext(name)
    if not base or not ext:
        return False
    ext = ext[1:].lower()
    return ext in ALLOWED_EXTS

if __name__ == "__main__":
    base = tempfile.mkdtemp(prefix="task129_py_")
    try:
        with open(os.path.join(base, "a.txt"), "w", encoding="utf-8") as f:
            f.write("Hello from Python\n")
        with open(os.path.join(base, "data.json"), "w", encoding="utf-8") as f:
            f.write('{"k": "v"}\n')
        with open(os.path.join(base, "doc.csv"), "w", encoding="utf-8") as f:
            f.write("c1,c2\n1,2\n")
        # Big file
        with open(os.path.join(base, "big.txt"), "wb") as f:
            f.write(b"A" * (MAX_FILE_SIZE + 5))

        tests = [
            "a.txt",          # valid
            "data.json",      # valid
            "../etc/passwd",  # traversal attempt
            "secret.conf",    # invalid extension
            "big.txt",        # too large
        ]

        for t in tests:
            try:
                content = fetch_file(base, t)
                print(f"FETCH OK [{t}]: {content.replace(chr(10), '\\n')}")
            except Exception as e:
                print(f"FETCH FAIL [{t}]: {e}")
    finally:
        shutil.rmtree(base, ignore_errors=True)