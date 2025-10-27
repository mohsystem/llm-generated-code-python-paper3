
import base64
import sqlite3
import os
import re

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif']

def upload_image(file_path, conn):
    """\n    Securely upload an image by reading it, converting to base64, and storing in database.\n    \n    Args:\n        file_path: Path to the image file\n        conn: Database connection object\n    \n    Returns:\n        Success message string\n    """
    # Validate file exists
    if not os.path.isfile(file_path):
        raise ValueError("Invalid file path")
    
    # Validate file size
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError("File size exceeds maximum allowed size")
    
    # Validate file extension
    file_name = os.path.basename(file_path)
    extension = get_file_extension(file_name).lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid file type. Allowed: {ALLOWED_EXTENSIONS}")
    
    # Sanitize filename
    sanitized_file_name = sanitize_filename(file_name)
    
    # Read and encode file
    with open(file_path, 'rb') as file:
        file_content = file.read()
    
    base64_string = base64.b64encode(file_content).decode('utf-8')
    
    # Insert into database using parameterized query
    cursor = conn.cursor()
    cursor.execute("INSERT INTO images (name, data) VALUES (?, ?)", 
                   (sanitized_file_name, base64_string))
    conn.commit()
    
    return f"Image uploaded successfully: {sanitized_file_name}"

def get_file_extension(file_name):
    """Extract file extension from filename."""
    parts = file_name.rsplit('.', 1)
    return parts[1] if len(parts) > 1 else ""

def sanitize_filename(file_name):
    """Remove potentially dangerous characters from filename."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', file_name)

if __name__ == "__main__":
    # Create test database
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS images \n                     (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, data TEXT)''')
    conn.commit()
    
    # Create test files
    def create_test_file(filename, size):
        with open(filename, 'wb') as f:
            f.write(b'\\xFF' * size)
    
    # Test Case 1: Valid image
    print("Test Case 1: Valid image")
    create_test_file("test1.jpg", 100)
    print(upload_image("test1.jpg", conn))
    
    # Test Case 2: Valid PNG
    print("\\nTest Case 2: Valid PNG")
    create_test_file("test2.png", 200)
    print(upload_image("test2.png", conn))
    
    # Test Case 3: Invalid extension
    print("\\nTest Case 3: Invalid extension")
    try:
        create_test_file("test3.exe", 100)
        upload_image("test3.exe", conn)
    except ValueError as e:
        print(f"Expected error: {e}")
    
    # Test Case 4: Non-existent file
    print("\\nTest Case 4: Non-existent file")
    try:
        upload_image("nonexistent.jpg", conn)
    except ValueError as e:
        print(f"Expected error: {e}")
    
    # Test Case 5: File with special characters
    print("\\nTest Case 5: File with special characters")
    create_test_file("test@#$5.jpg", 100)
    print(upload_image("test@#$5.jpg", conn))
    
    conn.close()
