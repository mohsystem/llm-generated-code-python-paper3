# Chain-of-Through Step 1: Problem understanding
# Implement upload_file to securely save an uploaded file into 'uploads' directory.

# Chain-of-Through Step 2: Security requirements handled within checks below.
import os
import re
import secrets

MAX_SIZE_BYTES = 1_000_000  # 1 MB for demo tests
ALLOWED_EXTS = {"txt", "png", "jpg", "jpeg", "pdf", "zip", "gif", "bmp", "csv", "json"}

def _sanitize_name(name: str) -> str:
    # Allow alnum, dot, underscore, hyphen
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', name)[:100]
    if not safe or safe.startswith('.'):
        safe = "file"
    return safe

def _get_ext(filename: str) -> str:
    base = os.path.basename(filename)
    if '.' not in base or base.startswith('.'):
        return ""
    return base.rsplit('.', 1)[1]

def _strip_ext(filename: str) -> str:
    base = os.path.basename(filename)
    if '.' not in base or base.startswith('.'):
        return base
    return base.rsplit('.', 1)[0]

def upload_file(original_filename: str, data: bytes, content_type: str) -> str:
    # Chain-of-Through Step 3: Secure coding generation
    if data is None:
        return "ERROR: No data provided"
    if len(data) == 0:
        return "ERROR: Empty file"
    if len(data) > MAX_SIZE_BYTES:
        return "ERROR: File too large"

    if not original_filename:
        return "ERROR: Missing filename"

    ext = _get_ext(original_filename).lower()
    if not ext or ext not in ALLOWED_EXTS:
        return "ERROR: Disallowed file extension"

    name_no_ext = _strip_ext(original_filename)
    safe_base = _sanitize_name(name_no_ext)
    unique = f"{safe_base}_{secrets.token_hex(8)}.{ext}"

    uploads = "uploads"
    try:
        os.makedirs(uploads, mode=0o700, exist_ok=True)
    except Exception:
        return "ERROR: Could not create uploads directory"

    target = os.path.normpath(os.path.join(uploads, unique))
    abs_uploads = os.path.abspath(uploads)
    abs_target = os.path.abspath(target)
    if not abs_target.startswith(abs_uploads + os.sep):
        return "ERROR: Invalid path"

    try:
        with open(target, "xb") as f:  # exclusive create
            f.write(data)
    except FileExistsError:
        return "ERROR: Name collision, try again"
    except Exception:
        return "ERROR: Write failed"

    # Chain-of-Through Step 4 and 5: Review and secure output
    return target

if __name__ == "__main__":
    # 5 test cases
    print("Test1:", upload_file("hello.txt", b"Hello World", "text/plain"))
    print("Test2:", upload_file("../../etc/passwd", b"fake", "text/plain"))  # No ext -> error
    print("Test3:", upload_file("image.png", b"\x89PNG", "image/png"))
    print("Test4:", upload_file("script.exe", b"MZ", "application/octet-stream"))  # Disallowed
    big = b"\x00" * (MAX_SIZE_BYTES + 1)
    print("Test5:", upload_file("big.pdf", big, "application/pdf"))