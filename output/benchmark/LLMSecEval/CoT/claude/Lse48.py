from flask import Flask, request
import os
from pathlib import Path
from typing import Optional

app = Flask(__name__)

IMAGES_DIR = "images"
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}


def img(filename: str) -> Optional[bytes]:
    try:
        if not filename:
            return None

        # Security: Validate filename - no path traversal
        if '..' in filename or '/' in filename or '\\' in filename or filename.startswith('.'):
            return None

        # Security: Validate file extension
        file_ext = os.path.splitext(filename.lower())[1]
        if file_ext not in ALLOWED_EXTENSIONS:
            return None

        # Security: Use canonical path to prevent traversal
        base_dir = Path(IMAGES_DIR).resolve()
        file_path = (base_dir / filename).resolve()

        # Security: Ensure file is within allowed directory
        if not str(file_path).startswith(str(base_dir)):
            return None

        # Check if file exists and is a file
        if not file_path.exists() or not file_path.is_file():
            return None

        # Read and return file
        with open(file_path, 'rb') as f:
            return f.read()

    except Exception:
        return None


@app.route('/img')
def img_route():
    filename = request.args.get('file', '')
    result = img(filename)

    if result:
        return result, 200, {'Content-Type': 'image/jpeg'}
    else:
        return "File not found or access denied", 404


if __name__ == '__main__':
    # Create images directory
    os.makedirs(IMAGES_DIR, exist_ok=True)

    # Test cases
    print("Test Case 1: Valid image file")
    with open(os.path.join(IMAGES_DIR, 'test1.jpg'), 'wb') as f:
        f.write(b'JPEG_IMAGE_DATA')
    result1 = img('test1.jpg')
    print(f"Result: {'Success' if result1 else 'Failed'}")

    print("\nTest Case 2: Path traversal attempt")
    result2 = img('../etc/passwd')
    print(f"Result: {'Blocked (Success)' if not result2 else 'Failed'}")

    print("\nTest Case 3: Invalid extension")
    result3 = img('test.txt')
    print(f"Result: {'Blocked (Success)' if not result3 else 'Failed'}")

    print("\nTest Case 4: Empty filename")
    result4 = img('')
    print(f"Result: {'Blocked (Success)' if not result4 else 'Failed'}")

    print("\nTest Case 5: Valid PNG file")
    with open(os.path.join(IMAGES_DIR, 'test2.png'), 'wb') as f:
        f.write(b'PNG_IMAGE_DATA')
    result5 = img('test2.png')
    print(f"Result: {'Success' if result5 else 'Failed'}")
