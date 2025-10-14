import os
import stat
import secrets
import time
from typing import Optional

MAX_SIZE = 5 * 1024 * 1024
ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "bin"}

def _sanitize_filename(name: str) -> str:
    cleaned = []
    for ch in name:
        if ch.isalnum() or ch in ['.', '_', '-']:
            cleaned.append(ch)
        else:
            cleaned.append('_')
    s = ''.join(cleaned)
    while s.startswith('.'):
        s = s[1:]
    if not s:
        s = "file"
    return s[:255]

def _allowed_ext_or_default(filename: str, default_ext: str) -> str:
    ext = ''
    if '.' in filename:
        ext = filename.rsplit('.', 1)[-1].lower()
    return ext if ext in ALLOWED_EXT else default_ext

def _set_owner_only_permissions(path: str, is_dir: bool):
    try:
        if is_dir:
            os.chmod(path, stat.S_IRWXU)
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

def upload_file(storage_dir: str, original_filename: str, content: bytes) -> str:
    if storage_dir is None or original_filename is None or content is None:
        raise ValueError("Invalid arguments.")
    if len(content) == 0:
        raise ValueError("File content is empty.")
    if len(content) > MAX_SIZE:
        raise ValueError(f"File too large. Limit is {MAX_SIZE} bytes.")

    # Ensure directory exists
    os.makedirs(storage_dir, exist_ok=True)
    _set_owner_only_permissions(storage_dir, True)

    safe_name = _sanitize_filename(original_filename)
    ext = _allowed_ext_or_default(safe_name, "bin")

    rand_hex = secrets.token_hex(16)
    unique_name = f"f-{int(time.time()*1000)}-{rand_hex}.{ext}"
    final_path = os.path.join(storage_dir, unique_name)

    # Write to a temp file then atomically replace
    tmp_path = os.path.join(storage_dir, f"upload-{secrets.token_hex(8)}.tmp")
    try:
        with open(tmp_path, 'xb') as f:
            f.write(content)
        _set_owner_only_permissions(tmp_path, False)
        try:
            os.replace(tmp_path, final_path)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        _set_owner_only_permissions(final_path, False)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    return f"Upload successful. Stored as {os.path.basename(final_path)} ({len(content)} bytes)."

if __name__ == "__main__":
    storage = "uploads_py"
    tests = [
        ("hello.txt", b"Hello World"),
        ("../../etc/passwd", b"Not a passwd"),
        ("image.PNG", bytes([1,2,3,4,5])),
        ("script.exe", b"binary data"),
        ("..hidden..file..name..pdf", secrets.token_bytes(MAX_SIZE + 1024)),  # too big
    ]
    for i, (name, data) in enumerate(tests, 1):
        try:
            msg = upload_file(storage, name, data)
            print(f"{i}: {msg}")
        except Exception as e:
            print(f"{i}: Upload failed: {e}")