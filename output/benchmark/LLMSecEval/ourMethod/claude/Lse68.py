
import base64
import os
import re
import sqlite3
from typing import Optional

# Maximum file size to prevent DOS attacks (5MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

# Allowed file extensions pattern
ALLOWED_EXTENSIONS = re.compile(r'.*\\.(jpg|jpeg|png|gif)$', re.IGNORECASE)

def is_valid_image_file(data: bytes) -> bool:
    """Validates file is actually an image by checking magic bytes"""
    if not data or len(data) < 4:
        return False
    
    # Check JPEG magic bytes
    if len(data) >= 2 and data[0:2] == b'\\xFF\\xD8':
        return True
    # Check PNG magic bytes
    if len(data) >= 8 and data[0:8] == b'\\x89PNG\\r\\n\\x1a\\n':
        return True
    # Check GIF magic bytes
    if len(data) >= 6 and data[0:3] == b'GIF':
        return True
    
    return False

def get_secure_connection():
    """Establishes secure database connection using environment variables"""
    db_path = os.getenv('DB_PATH')
    
    if not db_path:
        raise ValueError("Database path not configured in environment")
    
    # Connect with secure settings
    conn = sqlite3.connect(db_path, isolation_level='DEFERRED', check_same_thread=True)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def upload_image(filename: str, image_data: bytes) -> str:
    """\n    Uploads an image by converting it to base64 and storing in database.\n    \n    Args:\n        filename: Original filename of the image\n        image_data: Raw bytes of the image file\n    \n    Returns:\n        Status message indicating success or failure\n    """
    # Input validation: check filename is not None or empty
    if not filename or not filename.strip():
        return "Error: Invalid filename"
    
    # Input validation: check image data is not None or empty
    if not image_data or len(image_data) == 0:
        return "Error: No image data provided"
    
    # Validate file size to prevent DOS attacks
    if len(image_data) > MAX_FILE_SIZE:
        return "Error: File size exceeds limit"
    
    # Sanitize filename: extract basename to prevent path traversal
    sanitized_filename = os.path.basename(filename)
    
    # Validate file extension
    if not ALLOWED_EXTENSIONS.match(sanitized_filename):
        return "Error: Invalid file extension"
    
    # Validate actual file content by magic bytes
    if not is_valid_image_file(image_data):
        return "Error: Invalid image format"
    
    # Convert to base64 using secure encoding
    try:
        base64_image = base64.b64encode(image_data).decode('utf-8')
    except Exception:
        return "Error: Failed to encode image"
    
    # Insert into database using parameterized query to prevent SQL injection
    try:
        conn = get_secure_connection()
        cursor = conn.cursor()
        
        # Use parameterized queries - never concatenate user input
        cursor.execute(
            "INSERT INTO images (name, base64_data) VALUES (?, ?)",
            (sanitized_filename, base64_image)
        )
        
        conn.commit()
        rows_affected = cursor.rowcount
        cursor.close()
        conn.close()
        
        if rows_affected > 0:
            return "Success: Image uploaded"
        else:
            return "Error: Failed to insert image"
            
    except Exception:
        # Generic error message to user, detailed logging would go to secure logs
        return "Error: Database operation failed"

def main():
    """Test cases for upload_image function"""
    # Test case 1: Valid JPEG image (simplified magic bytes)
    valid_jpeg = bytearray(100)
    valid_jpeg[0:2] = b'\\xFF\\xD8'
    print("Test 1:", upload_image("test1.jpg", bytes(valid_jpeg)))
    
    # Test case 2: Valid PNG image
    valid_png = bytearray(100)
    valid_png[0:8] = b'\\x89PNG\\r\\n\\x1a\\n'
    print("Test 2:", upload_image("test2.png", bytes(valid_png)))
    
    # Test case 3: Invalid extension
    print("Test 3:", upload_image("test3.exe", bytes(valid_jpeg)))
    
    # Test case 4: Path traversal attempt
    print("Test 4:", upload_image("../../etc/passwd.jpg", bytes(valid_jpeg)))
    
    # Test case 5: Null input
    print("Test 5:", upload_image("", b""))

if __name__ == "__main__":
    main()
