import os
import re
from pathlib import Path

# Chain-of-Through process in code generation:
# 1) Problem understanding:
#    - Read a requested file only from a predefined safe directory.
# 2) Security requirements:
#    - Validate input; block absolute paths, NUL, disallowed chars.
#    - Ensure the resolved path remains in safe directory.
#    - Block symlink traversal and cap file size.
# 3) Secure coding generation: implemented in read_from_safe_dir.
# 4) Code review: checks include normalization, commonpath, and symlink detection.
# 5) Secure code output: final function and test harness.

MAX_SIZE_BYTES = 1_048_576  # 1 MiB
SAFE_DIR = (Path.home() / "safe_dir").resolve()

def read_from_safe_dir(requested_path: str):
    if not isinstance(requested_path, str):
        return None
    req = requested_path.strip()
    if not req:
        return None
    if "\x00" in req:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._/\-]+", req):
        return None

    try:
        SAFE_DIR.mkdir(parents=True, exist_ok=True)
        safe_real = SAFE_DIR.resolve(strict=True)
    except Exception:
        return None

    p_req = Path(req)
    if p_req.is_absolute():
        return None

    target = (SAFE_DIR / p_req).resolve(strict=False)

    # Must remain inside safe directory
    try:
        common = os.path.commonpath([str(safe_real), str(target)])
    except Exception:
        return None
    if common != str(safe_real):
        return None

    # Symlink checks on path components that exist
    cur = safe_real
    for part in p_req.parts:
        cur = cur / part
        try:
            if cur.exists() and cur.is_symlink():
                return None
        except Exception:
            return None

    # Ensure target exists and is a regular file
    try:
        if not target.exists() or not target.is_file():
            return None
        # Final real path and containment check (after resolving)
        target_real = target.resolve(strict=True)
        common2 = os.path.commonpath([str(safe_real), str(target_real)])
        if common2 != str(safe_real):
            return None

        size = target_real.stat().st_size
        if size < 0 or size > MAX_SIZE_BYTES:
            return None

        with open(target_real, "rb") as f:
            data = f.read(MAX_SIZE_BYTES + 1)
            if len(data) != size:
                return None
        return data.decode("utf-8")
    except Exception:
        return None

if __name__ == "__main__":
    tests = [
        "example.txt",
        "../secret.txt",
        "/etc/passwd",
        "subdir/notes.txt",
        "subdir/../../evil"
    ]
    for t in tests:
        result = read_from_safe_dir(t)
        print(f"Request: {t}")
        if result is not None:
            print(f"Read OK, length={len(result)}")
        else:
            print("Read FAILED")
        print("---")