import os
import mysql.connector
from mysql.connector import Error
from pathlib import Path
import sys

# --- Database Schema ---
# CREATE DATABASE IF NOT EXISTS image_db;
# USE image_db;
# CREATE TABLE IF NOT EXISTS images (
#     id INT AUTO_INCREMENT PRIMARY KEY,
#     filename VARCHAR(255) NOT NULL,
#     data LONGBLOB NOT NULL,
#     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
# );

# --- Installation ---
# pip install mysql-connector-python

# --- Database Configuration ---
# It's recommended to load these from a secure source like environment variables
# or a secrets manager, not hardcoded.
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_user',
    'password': 'your_password',
    'database': 'image_db'
}

# --- Security Configuration ---
# Define a base directory where images are allowed to be read from.
# Using a temporary directory for portable testing.
BASE_DIRECTORY = Path(os.path.join(os.getenv("TMP", "/tmp"), "image_uploads_safe_dir")).resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def store_image_in_db(unsafe_file_path: str) -> bool:
    """
    Stores an image file in the database after performing security checks.

    Args:
        unsafe_file_path: The path to the image file.

    Returns:
        True if successful, False otherwise.
    """
    if not unsafe_file_path:
        print("Error: File path is empty.", file=sys.stderr)
        return False

    try:
        # Rule #5: Validate path to prevent traversal attacks.
        # Resolve the path to its absolute, canonical form.
        file_path = Path(unsafe_file_path).resolve()

        # Check if the resolved path is within the allowed base directory.
        if BASE_DIRECTORY not in file_path.parents and file_path != BASE_DIRECTORY:
             print(f"Error: Path traversal attempt detected. '{file_path}' is outside of '{BASE_DIRECTORY}'.", file=sys.stderr)
             return False

    except (IOError, OSError) as e:
        print(f"Error resolving path: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred during path validation: {e}", file=sys.stderr)
        return False


    # Rule #6: Open first, then validate handle to prevent TOCTOU races.
    fd = -1
    try:
        # O_NOFOLLOW prevents following symbolic links, enhancing security.
        open_flags = os.O_RDONLY
        if hasattr(os, 'O_NOFOLLOW'):
            open_flags |= os.O_NOFOLLOW
            
        # os.open() is used for low-level, race-safe file opening.
        fd = os.open(file_path, open_flags)
        
        # Validate the opened file descriptor.
        stat_info = os.fstat(fd)
        
        # Check if it's a regular file using S_ISREG macro.
        if not (stat_info.st_mode & 0o100000): # S_ISREG
            print(f"Error: Path '{file_path}' is not a regular file.", file=sys.stderr)
            return False

        # Rule #1 & #3: Validate file size.
        if stat_info.st_size > MAX_FILE_SIZE:
            print(f"Error: File size {stat_info.st_size} bytes exceeds the limit of {MAX_FILE_SIZE} bytes.", file=sys.stderr)
            return False
            
        if stat_info.st_size == 0:
            print(f"Warning: File '{file_path}' is empty.", file=sys.stderr)
            # Decide if empty files are allowed. Here we allow them but you might want to return False.

        with os.fdopen(fd, 'rb') as f:
            image_data = f.read()
        fd = -1 # fd is now managed by the file object 'f' and will be closed by 'with'

    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'.", file=sys.stderr)
        return False
    except OSError as e:
        # ELOOP can happen if O_NOFOLLOW is not supported and there's a symlink loop.
        print(f"File system error opening '{file_path}': {e}", file=sys.stderr)
        return False
    finally:
        if fd != -1:
            os.close(fd)


    # --- Database Interaction ---
    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        if conn.is_connected():
            cursor = conn.cursor()
            
            # Rule #2: Use prepared statements (parameterized queries).
            sql = "INSERT INTO images (filename, data) VALUES (%s, %s)"
            # Use the original filename part, not the full path.
            args = (file_path.name, image_data)
            
            cursor.execute(sql, args)
            conn.commit()
            
            print(f"Successfully stored image: {file_path.name}")
            return True
    except Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        return False
    finally:
        if conn and conn.is_connected():
            conn.close()
    
    return False


def main():
    """Main function for testing."""
    # Setup test environment
    try:
        BASE_DIRECTORY.mkdir(parents=True, exist_ok=True)
        print(f"Created base directory for tests: {BASE_DIRECTORY}")
    except OSError as e:
        print(f"Failed to create test directory: {e}", file=sys.stderr)
        return

    valid_file = BASE_DIRECTORY / "test_image.jpg"
    large_file = BASE_DIRECTORY / "large_image.jpg"
    outside_file = Path(os.getenv("TMP", "/tmp")) / "outside_image.jpg"
    directory_path = BASE_DIRECTORY
    non_existent_file = BASE_DIRECTORY / "nonexistent.jpg"

    try:
        with open(valid_file, "wb") as f:
            f.write(b"dummy image data")
        with open(large_file, "wb") as f:
            f.seek(MAX_FILE_SIZE)
            f.write(b'\0') # Write one byte over the limit
        with open(outside_file, "wb") as f:
            f.write(b"should not be accessed")
        print("Created test files.")

        print("\n--- Running Test Cases ---")

        # Test Case 1: Valid file
        print("\n1. Testing with a valid file...")
        store_image_in_db(str(valid_file))

        # Test Case 2: File is too large
        print("\n2. Testing with a file that is too large...")
        store_image_in_db(str(large_file))

        # Test Case 3: Path traversal attempt
        print("\n3. Testing with a file outside the allowed directory...")
        store_image_in_db(str(outside_file))

        # Test Case 4: Non-existent file
        print("\n4. Testing with a non-existent file...")
        store_image_in_db(str(non_existent_file))
        
        # Test Case 5: Path is a directory
        print("\n5. Testing with a path that is a directory...")
        store_image_in_db(str(directory_path))

    except IOError as e:
        print(f"Error setting up test files: {e}", file=sys.stderr)
    finally:
        # Cleanup
        for p in [valid_file, large_file, outside_file]:
            if p.exists():
                p.unlink()
        print("\nCleaned up test files.")

if __name__ == "__main__":
    main()