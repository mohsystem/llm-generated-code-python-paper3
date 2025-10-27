import os
import re

BASE_DIR = os.path.abspath(os.path.join("static", "images"))
SAFE_NAME = re.compile(r'^[A-Za-z0-9._-]+$')
ALLOWED_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024

def img(file_param: str):
    if not file_param or not isinstance(file_param, str):
        return None
    if not SAFE_NAME.match(file_param):
        return None
    _, ext = os.path.splitext(file_param)
    ext = ext.lower()
    if ext not in ALLOWED_EXT:
        return None

    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        candidate = os.path.abspath(os.path.join(BASE_DIR, file_param))
        base_real = os.path.realpath(BASE_DIR)
        cand_real = os.path.realpath(candidate)
        if not cand_real.startswith(base_real + os.sep) and cand_real != base_real:
            return None
        if not os.path.isfile(cand_real):
            return None
        size = os.path.getsize(cand_real)
        if size > MAX_FILE_SIZE:
            return None
        with open(cand_real, 'rb') as f:
            return f.read()
    except Exception:
        return None

def _ensure_test_files():
    os.makedirs(BASE_DIR, exist_ok=True)
    f1 = os.path.join(BASE_DIR, "test1.png")
    if not os.path.exists(f1):
        with open(f1, "wb") as fp:
            fp.write(b"PNGDATA")
    f2 = os.path.join(BASE_DIR, "test2.txt")
    if not os.path.exists(f2):
        with open(f2, "wb") as fp:
            fp.write(b"TEXTDATA")

if __name__ == "__main__":
    _ensure_test_files()
    tests = [
        "test1.png",      # valid
        "../secret.txt",  # traversal
        "test2.txt",      # invalid extension
        "missing.jpg",    # missing
        "bad/evil.png"    # path separator
    ]
    for t in tests:
        out = img(t)
        print(f"{t} -> {len(out) if isinstance(out, (bytes, bytearray)) else 'None'}")