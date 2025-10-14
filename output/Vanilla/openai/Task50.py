import os
import re
import time
import uuid
from typing import Optional

UPLOAD_DIR = "uploads"

def upload_file(filename: str, data: bytes) -> str:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    safe = sanitize_filename(filename)
    unique = f"{int(time.time()*1000)}_{uuid.uuid4().hex}_{safe}"
    path = os.path.join(UPLOAD_DIR, unique)
    try:
        with open(path, "wb") as f:
            f.write(data)
        return f"OK: stored as {path} (name={filename}, size={len(data)} bytes)"
    except Exception as e:
        return f"ERROR: {e}"

def sanitize_filename(name: Optional[str]) -> str:
    if not name:
        name = "file"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not safe:
        safe = "file"
    return safe[:200]

if __name__ == "__main__":
    # 5 test cases
    print(upload_file("hello.txt", b"Hello, world!"))

    import os as _os
    img_mock = _os.urandom(256)
    print(upload_file("image.png", img_mock))

    print(upload_file("../report.pdf", b"This is a mock PDF content."))

    data_bin = _os.urandom(1024)
    print(upload_file("data.bin", data_bin))

    long_name = "resume_with_a_very_long_name_that_should_be_sanitized_and_truncated_if_needed_because_it_might_be_too_long_for_some_file_systems.docx"
    print(upload_file(long_name, b"Resume content bytes"))