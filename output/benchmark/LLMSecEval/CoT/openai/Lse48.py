# Chain-of-Through process in code generation:
# 1) Problem understanding: Implement img(file_param) to safely open a file in binary and return bytes like /img?file=<name>.
# 2) Security requirements: Enforce safe filename pattern, prevent path traversal, restrict to BASE_DIR.
# 3) Secure coding generation: Validate input, resolve real path, ensure it stays inside BASE_DIR, read in rb mode.
# 4) Code review: Avoid direct user path concatenation; handle exceptions; return b"" on error.
# 5) Secure code output: Final secured function with tests.

import os
import re
from pathlib import Path

BASE_DIR = Path("static").resolve()
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,255}$")

def img(file_param: str) -> bytes:
    try:
        if file_param is None:
            return b""
        if not SAFE_NAME.fullmatch(file_param):
            return b""
        if file_param in (".", ".."):
            return b""
        target = (BASE_DIR / file_param).resolve(strict=False)
        # Ensure the resolved path is under BASE_DIR (path traversal defense)
        if not str(target).startswith(str(BASE_DIR) + os.sep):
            return b""
        if not target.exists() or not target.is_file():
            return b""
        with open(target, "rb") as f:
            return f.read()
    except Exception:
        return b""

def _ensure_base_and_fixtures():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    f1 = BASE_DIR / "index.txt"
    if not f1.exists():
        f1.write_bytes(b"Hello from index\n")
    f2 = BASE_DIR / "image.bin"
    if not f2.exists():
        f2.write_bytes(bytes([(i * 7) & 0xFF for i in range(16)]))

def _print_result(label: str, data: bytes):
    head = list(data[:8]) if data else []
    print(f"{label} -> size={len(data)}, head={head}")

if __name__ == "__main__":
    _ensure_base_and_fixtures()
    # 5 test cases
    r1 = img("index.txt")           # valid
    r2 = img("image.bin")           # valid
    r3 = img("../etc/passwd")       # traversal -> empty
    r4 = img("bad$name.txt")        # invalid chars -> empty
    r5 = img("missing.txt")         # non-existent -> empty

    _print_result("TC1 index.txt", r1)
    _print_result("TC2 image.bin", r2)
    _print_result("TC3 ../etc/passwd", r3)
    _print_result("TC4 bad$name.txt", r4)
    _print_result("TC5 missing.txt", r5)