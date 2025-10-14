# Chain-of-Through process in code:
# 1) Problem understanding: Implement a secure file upload handler function that validates and saves files.
# 2) Security requirements: Limit size, whitelist extensions, magic-byte sniffing, sanitize name, prevent traversal, unique naming, safe writes, restrictive perms.
# 3) Secure coding generation: Build validation and I/O with try/except and robust checks.
# 4) Code review: Comments indicate protections; exceptions handled; no unsafe eval or shell usage.
# 5) Secure code output: Final code applies mitigations and demonstrates 5 test cases.

import os
import time
import secrets
from pathlib import Path
from typing import Optional

MAX_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXT = {"txt", "png", "jpg", "jpeg", "pdf"}

def upload_file(original_filename: str, data: bytes, dest_dir: str) -> Optional[str]:
    try:
        if not isinstance(original_filename, str) or not isinstance(data, (bytes, bytearray)):
            return None
        if len(data) == 0 or len(data) > MAX_SIZE:
            return None

        safe_name = _sanitize_filename(original_filename)
        ext = _get_ext(safe_name)
        if ext not in ALLOWED_EXT:
            return None

        if not _content_matches_ext(data, ext):
            return None

        dir_path = Path(dest_dir).resolve()
        dir_path.mkdir(parents=True, exist_ok=True)
        _set_restrictive_permissions(dir_path)

        base = _strip_ext(safe_name)
        final_name = f"{base}_{int(time.time()*1000)}_{secrets.token_hex(8)}.{ext}"
        final_path = (dir_path / final_name).resolve()

        if not str(final_path).startswith(str(dir_path)):
            return None

        tmp_name = f"upload_{secrets.token_hex(8)}.tmp"
        tmp_path = (dir_path / tmp_name).resolve()
        with open(tmp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _set_restrictive_permissions(tmp_path)

        os.replace(tmp_path, final_path)
        _set_restrictive_permissions(final_path)

        return str(final_path)
    except Exception:
        return None

def _sanitize_filename(name: str) -> str:
    # strip directory elements
    name = os.path.basename(name)
    if not name:
        name = "file"
    # allow only safe chars
    safe = []
    for ch in name:
        if ch.isalnum() or ch in "._-":
            safe.append(ch)
        else:
            safe.append("_")
    s = "".join(safe)
    if s in {".", "..", ""}:
        s = "file"
    if len(s) > 100:
        s = s[:100]
    return s

def _get_ext(name: str) -> Optional[str]:
    if "." not in name:
        return None
    ext = name.rsplit(".", 1)[1].lower()
    return ext if ext else None

def _strip_ext(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else name

def _content_matches_ext(data: bytes, ext: str) -> bool:
    if ext == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in {"jpg", "jpeg"}:
        return data.startswith(b"\xff\xd8\xff")
    if ext == "pdf":
        return data.startswith(b"%PDF-")
    if ext == "txt":
        return _is_likely_text(data)
    return False

def _is_likely_text(data: bytes) -> bool:
    if not data:
        return True
    printable = 0
    for b in data:
        if b in (9, 10, 13) or 32 <= b <= 126 or b >= 128:
            printable += 1
    return printable / len(data) > 0.95

def _set_restrictive_permissions(path: Path) -> None:
    try:
        if path.is_dir():
            os.chmod(path, 0o750)
        else:
            os.chmod(path, 0o640)
    except Exception:
        pass

if __name__ == "__main__":
    dest = "uploads_py"
    # 1) Valid text
    r1 = upload_file("hello.txt", b"Hello secure world\n", dest)
    print("Case1:", r1)

    # 2) Valid png
    r2 = upload_file("pic.png", b"\x89PNG\r\n\x1a\n\x00\x00", dest)
    print("Case2:", r2)

    # 3) Attempt traversal
    r3 = upload_file("../bad/name?.txt", b"ok", dest)
    print("Case3:", r3)

    # 4) Disallowed extension
    r4 = upload_file("program.exe", b"MZ", dest)
    print("Case4:", r4)

    # 5) Too large
    r5 = upload_file("big.txt", b"\x00" * (MAX_SIZE + 1), dest)
    print("Case5:", r5)