import os
import uuid
import re

UPLOAD_DIR = 'uploads'
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.png'}
# A basic whitelist for safe characters in a filename.
FILENAME_REGEX = re.compile(r'^[a-zA-Z0-9._-]+$')

def upload_file(filename, content):
    """
    Securely saves an uploaded file.

    :param filename: The original name of the file from the user.
    :param content: The binary content of the file.
    :return: The path to the saved file on success, or None on failure.
    """
    if not filename or not content:
        print("Error: Filename or content is empty.")
        return None

    # 1. Check file size
    if len(content) > MAX_FILE_SIZE:
        print(f"Error: File size exceeds the limit of {MAX_FILE_SIZE} bytes.")
        return None

    # 2. Sanitize filename to prevent path traversal
    # os.path.basename strips directory information, e.g., '../../'
    basename = os.path.basename(filename)

    # Check for null bytes
    if '\0' in basename:
        print("Error: Filename contains null byte.")
        return None
        
    # Additional check for potentially harmful characters
    if not FILENAME_REGEX.match(basename):
        print(f"Error: Filename '{basename}' contains invalid characters.")
        return None

    # 3. Validate file extension
    _, ext = os.path.splitext(basename)
    if not ext or ext.lower() not in ALLOWED_EXTENSIONS:
        print(f"Error: File type '{ext}' is not allowed.")
        return None

    try:
        # 4. Create the upload directory if it doesn't exist
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        # 5. Generate a unique filename to prevent overwrites
        unique_filename = f"{uuid.uuid4()}_{basename}"
        destination_path = os.path.join(UPLOAD_DIR, unique_filename)
        
        # Final check to ensure the path is within the upload directory
        # In this simple case os.path.join with a clean basename is safe,
        # but this is a good practice for more complex scenarios.
        if os.path.commonprefix([os.path.abspath(destination_path), os.path.abspath(UPLOAD_DIR)]) != os.path.abspath(UPLOAD_DIR):
            print("Error: Final path is outside the designated upload directory.")
            return None

        # 6. Save the file
        with open(destination_path, 'wb') as f:
            f.write(content)

        print(f"File saved successfully to: {os.path.abspath(destination_path)}")
        return destination_path

    except (IOError, OSError) as e:
        print(f"Error saving file: {e}")
        return None

def main():
    """Runs test cases for the upload_file function."""
    print("--- Running Test Cases ---")

    # Test Case 1: Normal, valid file upload
    print("\n[Test 1] Normal file upload")
    upload_file("document.pdf", b"This is a sample PDF content.")

    # Test Case 2: Path traversal attempt
    print("\n[Test 2] Path traversal attempt")
    upload_file("../../../root/.bashrc", b"alias ls='rm -rf ~' # MUAHAHA")

    # Test Case 3: File too large
    print("\n[Test 3] File too large")
    large_content = b'a' * (MAX_FILE_SIZE + 1)
    upload_file("large_image.jpg", large_content)

    # Test Case 4: Disallowed file type
    print("\n[Test 4] Disallowed file type")
    upload_file("exploit.exe", b"binary content of an executable")
    
    # Test Case 5: Filename with invalid characters
    print("\n[Test 5] Filename with invalid characters")
    upload_file("my vacation photo (!@#$).png", b"some image data")
    
    print("\n--- Test Cases Finished ---")

if __name__ == "__main__":
    main()