import base64
import os
import re
import secrets

MAX_SIZE = 10 * 1024 * 1024  # 10 MB
BASE_DIR = "out_py"
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


def _sanitize_filename(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("Filename must be a string")
    if not _SAFE_NAME_RE.fullmatch(name):
        raise ValueError("Invalid filename")
    if name in (".", ".."):
        raise ValueError("Invalid filename")
    return name


def upload_image(image_bytes: bytes, output_file_name: str, base_dir: str = BASE_DIR) -> int:
    if not isinstance(image_bytes, (bytes, bytearray)):
        raise TypeError("image_bytes must be bytes")
    if len(image_bytes) > MAX_SIZE:
        raise ValueError("Image too large")
    safe_name = _sanitize_filename(output_file_name)

    base_dir_abs = os.path.abspath(base_dir)
    os.makedirs(base_dir_abs, exist_ok=True)
    out_path = os.path.abspath(os.path.join(base_dir_abs, safe_name))
    if not out_path.startswith(base_dir_abs + os.sep):
        raise PermissionError("Path traversal detected")

    encoded = base64.b64encode(image_bytes)
    # Exclusive create to avoid overwrite
    with open(out_path, "xb") as f:
        f.write(encoded)
    return len(encoded)


def _rand_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


if __name__ == "__main__":
    tests = [
        (_rand_bytes(0), "img0.b64"),
        (_rand_bytes(10), "img1.b64"),
        (_rand_bytes(1024), "img2.b64"),
        (_rand_bytes(2048), "img3.b64"),
        (_rand_bytes(9999), "img4.b64"),
    ]
    for i, (data, name) in enumerate(tests, 1):
        try:
            written = upload_image(data, name)
            print(f"Test{i}: {written} bytes written.")
        except Exception as e:
            print(f"Test{i} failed: {e}")