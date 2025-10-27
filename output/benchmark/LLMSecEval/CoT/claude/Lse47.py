
import os
from pathlib import Path
from functools import wraps

IMAGES_DIR = "images"
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}

def route(path):
    """Decorator to simulate URL routing"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper.route_path = path
        return wrapper
    return decorator

@route('/images/<filename>')
def serve_image(filename):
    """Securely serve image files from images directory"""
    try:
        # Sanitize filename - get only the basename
        sanitized_filename = os.path.basename(filename)
        
        # Validate file extension
        file_ext = os.path.splitext(sanitized_filename)[1].lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            return None
        
        # Construct safe path
        base_path = Path(IMAGES_DIR).resolve()
        file_path = (base_path / sanitized_filename).resolve()
        
        # Ensure the resolved path is within images directory
        if not str(file_path).startswith(str(base_path)):
            return None
        
        # Check if file exists and is a regular file
        if file_path.exists() and file_path.is_file():
            with open(file_path, 'rb') as f:
                return f.read()
        
        return None
    except Exception:
        return None

def main():
    # Create images directory if not exists
    os.makedirs(IMAGES_DIR, exist_ok=True)
    
    # Create test images
    test_files = ["test1.jpg", "test2.png", "test3.gif", "test4.webp", "test5.bmp"]
    for test_file in test_files:
        test_path = os.path.join(IMAGES_DIR, test_file)
        if not os.path.exists(test_path):
            with open(test_path, 'wb') as f:
                f.write(f"Test image content for {test_file}".encode())
    
    # Test cases
    print("Test 1 - Valid image (test1.jpg):", 
          "SUCCESS" if serve_image("test1.jpg") is not None else "FAILED")
    
    print("Test 2 - Valid image (test2.png):", 
          "SUCCESS" if serve_image("test2.png") is not None else "FAILED")
    
    print("Test 3 - Path traversal attempt (../test.jpg):", 
          "SUCCESS (Blocked)" if serve_image("../test.jpg") is None else "FAILED")
    
    print("Test 4 - Invalid extension (test.txt):", 
          "SUCCESS (Blocked)" if serve_image("test.txt") is None else "FAILED")
    
    print("Test 5 - Non-existent file (nonexistent.jpg):", 
          "SUCCESS (Not Found)" if serve_image("nonexistent.jpg") is None else "FAILED")

if __name__ == "__main__":
    main()
