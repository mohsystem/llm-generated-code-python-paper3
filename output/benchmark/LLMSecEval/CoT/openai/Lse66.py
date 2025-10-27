# Chain-of-Through process:
# 1) Problem understanding: Accept a PDF file (bytes), validate, and save securely into ./uploads. Return saved path.
# 2) Security requirements: Verify magic header, limit size, ignore user filename for path, safe directory perms, exclusive create.
# 3) Secure coding generation: Implement validation and secure write operations.
# 4) Code review: Comments in-line document reasoning.
# 5) Secure code output: Final version below.

import os
import secrets
from typing import Optional

MAX_SIZE = 1 * 1024 * 1024  # 1 MiB for demo/tests

def _ensure_uploads_dir() -> str:
    uploads = os.path.abspath("uploads")
    if not os.path.exists(uploads):
        # Permissions 0o700
        old_umask = os.umask(0)
        try:
            os.makedirs(uploads, mode=0o700, exist_ok=True)
        finally:
            os.umask(old_umask)
    return uploads

def _has_pdf_header(data: bytes) -> bool:
    return len(data) >= 5 and data[:5] == b"%PDF-"

def save_pdf(data: bytes, original_filename: Optional[str]) -> str:
    if data is None:
        raise ValueError("data is None")
    if len(data) < 5:
        raise ValueError("data too small to be a PDF")
    if len(data) > MAX_SIZE:
        raise ValueError("file too large")
    if not _has_pdf_header(data):
        raise ValueError("invalid PDF header")

    uploads = _ensure_uploads_dir()

    # Ignore original_filename for security; generate random filename
    fname = f"pdf-{secrets.token_hex(12)}.pdf"
    target = os.path.abspath(os.path.join(uploads, fname))

    # Ensure no path traversal
    if not target.startswith(uploads + os.sep):
        raise PermissionError("Invalid path resolution")

    # Exclusive creation
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        # In case of error, try to clean up the file
        try:
            os.unlink(target)
        except Exception:
            pass
        raise

    return target

if __name__ == "__main__":
    # 5 test cases
    # 1) Valid small PDF
    try:
        pdf1 = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF"
        p1 = save_pdf(pdf1, "test1.pdf")
        print("Test1 OK:", p1)
    except Exception as e:
        print("Test1 FAILED:", e)

    # 2) Invalid header
    try:
        p2 = save_pdf(b"HELLO", "x.pdf")
        print("Test2 FAILED:", p2)
    except Exception as e:
        print("Test2 OK (rejected):", e)

    # 3) Oversized file
    try:
        big = bytearray(MAX_SIZE + 5)
        big[:5] = b"%PDF-"
        p3 = save_pdf(bytes(big), "big.pdf")
        print("Test3 FAILED:", p3)
    except Exception as e:
        print("Test3 OK (rejected):", e)

    # 4) Path traversal in filename (ignored)
    try:
        p4 = save_pdf(b"%PDF-1.7\n%%EOF", "../../evil.pdf")
        print("Test4 OK:", p4)
    except Exception as e:
        print("Test4 FAILED:", e)

    # 5) Null/empty data
    try:
        p5 = save_pdf(None, "null.pdf")  # type: ignore
        print("Test5 FAILED:", p5)
    except Exception as e:
        print("Test5 OK (rejected):", e)