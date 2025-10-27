# Steps (Chain-of-Through):
# 1) Problem understanding: upload_image() reads an image, encodes to base64, writes encoded to a file.
# 2) Security requirements: Validate input size, extension, signature, and constrain output path to CWD.
# 3) Secure coding generation: Careful file I/O, error handling, and path normalization.
# 4) Code review: Avoid path traversal, large memory, bad types.
# 5) Secure code output: Final implementation with tests.

import os
import base64
from pathlib import Path

ALLOWED_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
MAX_SIZE = 10 * 1024 * 1024  # 10 MB

def _has_allowed_extension(name: str) -> bool:
    name = name.lower()
    return any(name.endswith(ext) for ext in ALLOWED_EXTS)

def _allowed_signature(head: bytes) -> bool:
    if len(head) < 12:
        return False
    # PNG
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    # JPEG
    if head[0:3] == b"\xFF\xD8\xFF":
        return True
    # GIF
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return True
    # BMP
    if head.startswith(b"BM"):
        return True
    # WEBP: "RIFF" .... "WEBP"
    if head[0:4] == b"RIFF" and head[8:12] == b"WEBP":
        return True
    return False

def upload_image(input_path: str, output_path: str) -> str:
    if input_path is None or output_path is None:
        raise ValueError("Paths must not be None")

    in_p = Path(input_path)
    if not in_p.is_file():
        raise FileNotFoundError("Input is not a regular file")

    size = in_p.stat().st_size
    if size <= 0 or size > MAX_SIZE:
        raise ValueError("Invalid file size")

    if not _has_allowed_extension(in_p.name):
        raise ValueError("Disallowed file extension")

    with in_p.open('rb') as f:
        head = f.read(12)
        if len(head) < 12:
            raise ValueError("File too small or truncated")
    if not _allowed_signature(head):
        raise ValueError("Invalid or unsupported image signature")

    data = in_p.read_bytes()
    encoded = base64.b64encode(data).decode('ascii')

    cwd = Path.cwd().resolve()
    out_p = Path(output_path).resolve()
    # Ensure output is within current directory
    if os.path.commonpath([str(cwd)]) != os.path.commonpath([str(cwd), str(out_p.parent)]):
        raise ValueError("Output path escapes working directory")

    out_p.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_p.with_suffix(out_p.suffix + ".tmp")
    tmp.write_text(encoded, encoding='ascii')
    if out_p.exists():
        out_p.unlink()
    tmp.replace(out_p)

    return encoded

if __name__ == "__main__":
    # Prepare test data: 1x1 PNG (base64)
    png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMBAe0BqZcAAAAASUVORK5CYII="
    png_bytes = base64.b64decode(png_b64)

    in_dir = Path("test_inputs_py").resolve()
    out_dir = Path("encoded_outputs_py").resolve()
    in_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    in_names = ["img1.png", "img2.PNG", "img3.pNg", "img4.png", "img5.png"]
    out_names = ["img1.b64", "img2.b64", "img3.b64", "img4.b64", "img5.b64"]

    for name in in_names:
        (in_dir / name).write_bytes(png_bytes)

    for i in range(5):
        encoded = upload_image(str(in_dir / in_names[i]), str(out_dir / out_names[i]))
        print(f"Test {i+1} -> output: {out_dir / out_names[i]} (encoded length={len(encoded)})")