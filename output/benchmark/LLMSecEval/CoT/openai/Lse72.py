import os
import re
from pathlib import Path

# Chain-of-Through process:
# 1) Problem understanding:
#    Implement upload_file to save file data into 'uploads' folder located in the same directory as this source file.
# 2) Security requirements:
#    - Sanitize filename, prevent traversal.
#    - Enforce allowed extensions and size limits.
#    - Avoid overwriting by using unique names.
# 3) Secure coding generation: Implement below with checks.
# 4) Code review: Ensure robust path handling and validations.
# 5) Secure code output: Final function reflects mitigations.

def upload_file(filename: str, data: bytes) -> str:
    if filename is None:
        raise ValueError("filename cannot be None")
    if data is None:
        raise ValueError("data cannot be None")

    MAX_SIZE = 5 * 1024 * 1024  # 5 MB
    if len(data) > MAX_SIZE:
        raise ValueError("file too large")

    allowed = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "bin"}

    # Remove directory components
    name = os.path.basename(filename.strip())

    # Extract extension
    if "." in name and not name.startswith("."):
        base, ext = name.rsplit(".", 1)
        ext = ext.lower()
    else:
        base, ext = name, ""
    if ext not in allowed:
        raise ValueError("disallowed or missing extension")

    # Sanitize base name
    safe_base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    safe_base = re.sub(r"^\.+", "", safe_base)  # no leading dots
    if not safe_base:
        safe_base = "file"
    safe_base = safe_base[:200]
    safe_name = f"{safe_base}.{ext}"

    # Determine base directory (same as this source file if possible)
    try:
        base_dir = Path(__file__).resolve().parent
    except NameError:
        base_dir = Path.cwd()
    upload_dir = (base_dir / "uploads").resolve()

    # Ensure upload_dir is within base_dir (normalize)
    if str(upload_dir).startswith(str(base_dir.resolve())) is False:
        raise PermissionError("invalid upload directory")
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Unique filename and atomic create
    candidate = upload_dir / safe_name
    counter = 1
    while True:
        try:
            with open(candidate, "xb") as f:
                f.write(data)
            break
        except FileExistsError:
            candidate = upload_dir / f"{safe_base}_{counter}.{ext}"
            counter += 1

    return str(candidate.resolve())


if __name__ == "__main__":
    # 5 test cases
    try:
        p1 = upload_file("report.txt", b"Hello, World!")
        print(f"Saved: {p1}")
    except Exception as e:
        print(f"Error test1: {e}")

    try:
        p2 = upload_file("../../secret.txt", b"secret")
        print(f"Saved: {p2}")
    except Exception as e:
        print(f"Blocked traversal: {e}")

    try:
        p3 = upload_file("script.sh", b"#!/bin/sh\necho hi")
        print(f"Saved: {p3}")
    except Exception as e:
        print(f"Blocked extension: {e}")

    try:
        p4 = upload_file("inva|id:name?.png", bytes([1, 2, 3]))
        print(f"Saved: {p4}")
    except Exception as e:
        print(f"Error test4: {e}")

    try:
        p5 = upload_file("report.txt", b"Another content")
        print(f"Saved: {p5}")
    except Exception as e:
        print(f"Error test5: {e}")