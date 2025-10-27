
from flask import Flask, request, send_file, abort
import os
import re
from pathlib import Path

app = Flask(__name__)

IMAGES_DIR = "images"
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+\\.(jpg|jpeg|png|gif|bmp)$')

def is_valid_filename(filename):
    """Validate filename to prevent path traversal and restrict to images"""
    if not filename or not SAFE_FILENAME_PATTERN.match(filename):
        return False
    return True

@app.route('/img')
def img():
    """Secure image serving endpoint"""
    name = request.args.get('name')
    
    if not name or not is_valid_filename(name):
        abort(400, "Invalid filename")
    
    # Prevent path traversal by normalizing and checking path
    image_path = Path(IMAGES_DIR) / name
    images_dir = Path(IMAGES_DIR).resolve()
    
    try:
        resolved_path = image_path.resolve()
        if not str(resolved_path).startswith(str(images_dir)):
            abort(403, "Access denied")
        
        if not resolved_path.exists():
            abort(404, "File not found")
        
        return send_file(resolved_path)
    except Exception as e:
        abort(500, "Internal server error")

def setup_test_environment():
    """Create test directory and files"""
    os.makedirs(IMAGES_DIR, exist_ok=True)
    with open(os.path.join(IMAGES_DIR, "test1.jpg"), "wb") as f:
        f.write(b"Fake JPG content")
    with open(os.path.join(IMAGES_DIR, "test2.png"), "wb") as f:
        f.write(b"Fake PNG content")

if __name__ == '__main__':
    setup_test_environment()
    print("Test cases:")
    print("1. Valid: http://localhost:5000/img?name=test1.jpg")
    print("2. Valid: http://localhost:5000/img?name=test2.png")
    print("3. Invalid (path traversal): http://localhost:5000/img?name=../etc/passwd")
    print("4. Invalid (wrong extension): http://localhost:5000/img?name=test.txt")
    print("5. Non-existent: http://localhost:5000/img?name=nonexistent.jpg")
    app.run(debug=False, port=5000)
