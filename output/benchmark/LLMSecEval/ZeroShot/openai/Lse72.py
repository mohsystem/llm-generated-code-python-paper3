import os
import re
import sys
import uuid

WINDOWS_RESERVED = {
    "CON","PRN","AUX","NUL",
    "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
    "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"
}
ALLOWED_RE = re.compile(r'[^A-Za-z0-9._-]')

def _program_dir():
    try:
        return os.path.abspath(os.path.dirname(__file__))
    except NameError:
        return os.path.abspath(os.getcwd())

def _sanitize_filename(filename: str) -> str:
    if filename is None:
        filename = ""
    filename = filename.replace("\x00", "")
    base = os.path.basename(filename)
    if not base:
        base = "upload.bin"
    # replace disallowed chars
    cleaned = ALLOWED_RE.sub("_", base)
    if not cleaned:
        cleaned = "upload.bin"
    if cleaned.startswith("."):
        cleaned = "_" + cleaned[1:]

    # split name/ext
    name, ext = os.path.splitext(cleaned)
    if not name:
        name = "upload"
    # windows reserved base name
    if name.upper() in WINDOWS_RESERVED:
        name = "_" + name
    # default extension if none
    if not ext:
        ext = ".bin"
    # limit total length to 255
    total = name + ext
    if len(total) > 255:
        name = name[:max(1, 255 - len(ext))]
        total = name + ext
    return total

def upload_file(data: bytes, filename: str) -> str:
    if data is None:
        raise ValueError("data cannot be None")
    safe = _sanitize_filename(filename)
    base_dir = _program_dir()
    uploads_dir = os.path.join(base_dir, "uploads")
    os.makedirs(uploads_dir, exist_ok=True)

    name, ext = os.path.splitext(safe)
    counter = 0
    while True:
        candidate = f"{name}{ext}" if counter == 0 else f"{name}-{counter}{ext}"
        path = os.path.join(uploads_dir, candidate)
        try:
            # 'xb' ensures exclusive creation
            with open(path, "xb") as f:
                f.write(data)
            return os.path.abspath(path)
        except FileExistsError:
            counter += 1

if __name__ == "__main__":
    tests = [
        (b"Hello, world!", "greeting.txt"),
        (b"Another content", "../evil.txt"),
        (b"Malicious path attempt", "/etc/passwd"),
        (b"Absolute path attempt", "COM1"),
        (b"Special chars & spaces", "my file (final)!.pdf"),
    ]
    for d, n in tests:
        print(upload_file(d, n))