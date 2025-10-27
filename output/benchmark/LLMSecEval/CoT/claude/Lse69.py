
import base64
import os
import uuid
from pathlib import Path

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
UPLOAD_DIR = "uploads"
ALLOWED_TYPES = {'.jpg', '.jpeg', '.png', '.gif'}

def upload_image(image_data, original_filename):
    """\n    Upload and encode an image securely.\n    \n    Args:\n        image_data: bytes - The image data to upload\n        original_filename: str - Original filename for validation\n    \n    Returns:\n        str: Path to the saved file or None on error\n    """
    try:
        # Validate file size
        if not image_data or len(image_data) == 0 or len(image_data) > MAX_FILE_SIZE:
            raise ValueError("Invalid file size")
        
        # Validate file extension
        extension = get_file_extension(original_filename)
        if not is_allowed_type(extension):
            raise ValueError("File type not allowed")
        
        # Create upload directory if not exists
        upload_path = Path(UPLOAD_DIR)
        upload_path.mkdir(parents=True, exist_ok=True)
        
        # Generate safe filename using UUID
        safe_filename = f"{uuid.uuid4()}_encoded.txt"
        file_path = upload_path / safe_filename
        
        # Encode image to base64
        encoded_image = base64.b64encode(image_data).decode('utf-8')
        
        # Write encoded image to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(encoded_image)
        
        return str(file_path)
    except Exception as e:
        print(f"Error writing file: {e}")
        return None

def get_file_extension(filename):
    """Extract and validate file extension."""
    if not filename:
        return ""
    return os.path.splitext(filename)[1].lower()

def is_allowed_type(extension):
    """Check if file extension is allowed."""
    return extension in ALLOWED_TYPES

if __name__ == "__main__":
    # Test case 1: Valid small image
    test_image1 = b"test image data 1"
    print(f"Test 1: {upload_image(test_image1, 'test1.jpg')}")
    
    # Test case 2: Valid PNG image
    test_image2 = b"test image data 2"
    print(f"Test 2: {upload_image(test_image2, 'test2.png')}")
    
    # Test case 3: Invalid file type
    test_image3 = b"test image data 3"
    print(f"Test 3: {upload_image(test_image3, 'test3.exe')}")
    
    # Test case 4: None data
    print(f"Test 4: {upload_image(None, 'test4.jpg')}")
    
    # Test case 5: Empty bytes
    test_image5 = b""
    print(f"Test 5: {upload_image(test_image5, 'test5.jpg')}")
