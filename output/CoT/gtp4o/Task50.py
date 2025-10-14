import os
import re
import secrets

# Chain-of-Through process:
# 1) Understand: Store uploaded files on server securely and confirm storage.
# 2) Security: Validate name, restrict size and extensions, prevent traversal, use unique names, restrictive permissions.
# 3) Implement securely with os.path.basename, controlled directory, and exclusive create.
# 4) Review: Ensure all edge cases handled and errors returned without leaking sensitive info.
# 5) Output: Final secure function and tests.

MAX_SIZE = 10 * 1024 * 1024  # 10 MB
UPLOAD_DIR = "uploads"
ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "bin", "dat"}

def _sanitize_filename(name: str) -> str | None:
    base = os.path.basename(name)
    base = base.replace("\\", "").replace("/", "")
    if ".." in base:
        return None
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if not cleaned or len(cleaned) > 100:
        return None
    return cleaned

def _get_extension(name: str) -> str:
    if "." not in name:
        return ""
    ext = name.rsplit(".", 1)[1].lower()
    return ext

def upload_file(original_file_name: str, content: bytes) -> str:
    if not original_file_name or not isinstance(original_file_name, str):
        return "ERROR: Invalid file name."
    if content is None:
        return "ERROR: No content provided."
    if len(content) > MAX_SIZE:
        return f"ERROR: File too large. Max size is {MAX_SIZE} bytes."

    safe = _sanitize_filename(original_file_name)
    if not safe:
        return "ERROR: Invalid file name."

    ext = _get_extension(safe)
    if ext not in ALLOWED_EXT:
        return "ERROR: Disallowed or missing file extension."

    base = safe[:-(len(ext) + 1)] if ext else safe
    if not base:
        base = "file"
    if len(base) > 64:
        base = base[:64]

    # Ensure uploads dir exists with restrictive perms
    try:
        if not os.path.isdir(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR, mode=0o700, exist_ok=True)
        else:
            try:
                os.chmod(UPLOAD_DIR, 0o700)
            except Exception:
                pass
    except Exception:
        return "ERROR: Could not create upload directory."

    # Create unique name and write with exclusive create
    for _ in range(10):
        suffix = secrets.token_hex(8)
        final_name = f"{base}-{suffix}.{ext}"
        path = os.path.join(UPLOAD_DIR, final_name)
        try:
            with open(path, "xb") as f:
                f.write(content)
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            return f"OK: Stored as {UPLOAD_DIR}/{final_name} (size {len(content)} bytes)."
        except FileExistsError:
            continue
        except Exception:
            return "ERROR: Failed to store file."
    return "ERROR: Could not store file after multiple attempts."

if __name__ == "__main__":
    # 5 test cases
    print(upload_file("hello.txt", b"Hello, world!"))
    print(upload_file("../evil.txt", b"malicious"))
    print(upload_file("report.pdf", b"%PDF"))
    print(upload_file("image.png", b"\x00" * (MAX_SIZE + 1)))
    print(upload_file("bad?.txt", b"content"))