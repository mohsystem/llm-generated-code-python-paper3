
import os
from pathlib import Path

IMAGES_FOLDER = "images"

def serve_image(filename):
    """\n    Decorator-style function to check if file exists and return its content\n    """
    file_path = os.path.join(IMAGES_FOLDER, filename)
    
    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return None
    else:
        return None

def check_file_exists(filename):
    """\n    Check if file exists in images folder\n    """
    file_path = os.path.join(IMAGES_FOLDER, filename)
    return os.path.exists(file_path) and os.path.isfile(file_path)

if __name__ == "__main__":
    # Create test images folder
    os.makedirs(IMAGES_FOLDER, exist_ok=True)
    
    # Test cases
    test_files = [
        "image1.jpg",
        "image2.png",
        "nonexistent.jpg",
        "test.gif",
        "photo.bmp"
    ]
    
    print("Testing file existence and serving:")
    for filename in test_files:
        exists = check_file_exists(filename)
        print(f"File: {filename} - Exists: {exists}")
        
        content = serve_image(filename)
        if content is not None:
            print(f"  -> File served successfully, size: {len(content)} bytes")
        else:
            print(f"  -> File not found or error occurred")
