import os
import secrets

MAX_SIZE_BYTES = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
UPLOAD_DIR = "uploads"

def _sanitize_filename(name: str) -> str:
    # Basic traversal check
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError("Invalid filename (path traversal detected).")
    # Keep only safe chars
    safe = "".join(ch for ch in os.path.basename(name) if ch.isalnum() or ch in "._-")
    while safe.startswith("."):
        safe = safe[1:]
    if "." not in safe:
        raise ValueError("Filename must contain an extension.")
    base, ext = safe.rsplit(".", 1)
    ext = ext.lower()
    if len(ext) == 0 or len(ext) > 10:
        raise ValueError("Invalid extension length.")
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Disallowed file extension.")
    if len(safe) > 255:
        safe = safe[-255:]
    return base, ext

def _ensure_upload_dir():
    os.makedirs(UPLOAD_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(UPLOAD_DIR, 0o700)
    except Exception:
        pass

def upload_file(original_name: str, content: bytes) -> str:
    if original_name is None or content is None:
        raise ValueError("Filename and content must not be null.")
    if len(content) == 0:
        raise ValueError("Empty content not allowed.")
    if len(content) > MAX_SIZE_BYTES:
        raise ValueError("File exceeds maximum allowed size.")
    base, ext = _sanitize_filename(original_name)
    _ensure_upload_dir()
    unique = f"{secrets.token_hex(16)}.{ext}"
    dest = os.path.join(UPLOAD_DIR, unique)
    dest_abs = os.path.abspath(dest)
    uploads_abs = os.path.abspath(UPLOAD_DIR) + os.sep
    if not dest_abs.startswith(uploads_abs):
        raise ValueError("Resolved path escapes upload directory.")
    fd = None
    try:
        fd = os.open(dest_abs, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        total = 0
        while total < len(content):
            written = os.write(fd, content[total:])
            if written <= 0:
                raise OSError("Write failed.")
            total += written
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
    return dest_abs

if __name__ == "__main__":
    tests = [
        ("hello.txt", b"Hello, World!"),
        ("image.jpg", bytes([0xFF, 0xD8, 0xFF, 0xD9])),
        ("report.pdf", b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"),
        ("evil/../secret.txt", b"top secret"),
        ("malware.exe", b"MZ\x00\x00"),
    ]
    for name, data in tests:
        try:
            path = upload_file(name, data)
            print(f"Saved: {path}")
        except Exception as e:
            print(f"Failed: {name} -> {e}")