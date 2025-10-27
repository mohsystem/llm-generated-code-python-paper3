
import sqlite3
import base64
import os
from pathlib import Path

DB_PATH = "images.db"

def init_database():
    """Initialize the database with images table"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS images (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                name TEXT NOT NULL,\n                image_data TEXT NOT NULL\n            )\n        ''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")

def upload_image(image_path):
    """\n    Securely upload an image by reading it, converting to base64,\n    and storing in database\n    \n    Args:\n        image_path: Path to the image file\n        \n    Returns:\n        bool: True if upload successful, False otherwise\n    """
    # Input validation
    if not image_path or not isinstance(image_path, str):
        print("Invalid image path")
        return False
    
    # Validate file exists and is readable
    if not os.path.exists(image_path):
        print("File does not exist")
        return False
    
    if not os.path.isfile(image_path):
        print("Path is not a file")
        return False
    
    # Validate file size (max 5MB)
    if os.path.getsize(image_path) > 5 * 1024 * 1024:
        print("File size exceeds 5MB limit")
        return False
    
    # Validate file extension
    valid_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    file_extension = Path(image_path).suffix.lower()
    if file_extension not in valid_extensions:
        print("Invalid file type. Only JPG, PNG, and GIF allowed")
        return False
    
    try:
        # Read image file
        with open(image_path, 'rb') as image_file:
            image_bytes = image_file.read()
        
        # Convert to base64
        base64_image = base64.b64encode(image_bytes).decode('utf-8')
        
        # Get filename
        file_name = os.path.basename(image_path)
        
        # Insert into database using parameterized query (prevents SQL injection)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO images (name, image_data) VALUES (?, ?)",
            (file_name, base64_image)
        )
        conn.commit()
        conn.close()
        
        print(f"Image uploaded successfully: {file_name}")
        return True
        
    except IOError as e:
        print(f"Error reading image file: {e}")
        return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

if __name__ == "__main__":
    # Initialize database
    init_database()
    
    # Test cases
    print("Test Case 1: Valid image (create a test.jpg file first)")
    upload_image("test.jpg")
    
    print("\\nTest Case 2: None path")
    upload_image(None)
    
    print("\\nTest Case 3: Empty path")
    upload_image("")
    
    print("\\nTest Case 4: Non-existent file")
    upload_image("nonexistent.jpg")
    
    print("\\nTest Case 5: Invalid file type")
    upload_image("test.txt")
