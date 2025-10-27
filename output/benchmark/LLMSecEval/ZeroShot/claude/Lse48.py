
import os
import re
from pathlib import Path

ALLOWED_DIRECTORY = "./images/"

def img(file_param):
    """\n    Secure implementation of image file reading with path traversal protection\n    """
    if not file_param:
        print("File parameter is required", file=sys.stderr)
        return None
    
    # Secure: Sanitize input to prevent path traversal
    sanitized_file = re.sub(r'[^a-zA-Z0-9._-]', '', file_param)
    
    # Prevent path traversal attempts
    if '..' in sanitized_file or '/' in sanitized_file or '\\\\' in sanitized_file:
        print("Invalid file name", file=sys.stderr)
    return None

    try:
        # Construct the full path
        allowed_path = Path(ALLOWED_DIRECTORY).resolve()
        file_path = (allowed_path / sanitized_file).resolve()

        # Ensure the file is within allowed directory
        if not str(file_path).startswith(str(allowed_path)):
            print("Access denied: Path traversal attempt detected", file=sys.stderr)
            return None

        # Check if file exists and is readable
        if not file_path.exists() or not file_path.is_file():
            print("File not found or not readable", file=sys.stderr)
            return None

        # Read file in binary mode
        with open(file_path, 'rb') as f:
            return f.read()

    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    import sys

    # Create test directory and files
    os.makedirs(ALLOWED_DIRECTORY, exist_ok=True)

    try:
        with open(os.path.join(ALLOWED_DIRECTORY, "test1.txt"), 'wb') as f:
            f.write(b"Test content 1")
        with open(os.path.join(ALLOWED_DIRECTORY, "test2.jpg"), 'wb') as f:
            f.write(b"Image content")
    except Exception as e:
        print(f"Setup error: {e}", file=sys.stderr)


    # Test case 1: Valid file
    print("Test 1 - Valid file:")
    result1 = img("test1.txt")
    print("Success:", result1.decode() if result1 else "Failed")
    
    # Test case 2: Another valid file
    print("\\nTest 2 - Valid image file:")
    result2 = img("test2.jpg")
    print("Success:", result2.decode() if result2 else "Failed")
    
    # Test case 3: Path traversal attempt (should be blocked)
    print("\\nTest 3 - Path traversal attempt:")
    result3 = img("../etc/passwd")
    print("Blocked (Expected)" if not result3 else "Success")
    
    # Test case 4: None parameter
    print("\\nTest 4 - None parameter:")
    result4 = img(None)
    print("Blocked (Expected)" if not result4 else "Success")
    
    # Test case 5: Non-existent file
    print("\\nTest 5 - Non-existent file:")
    result5 = img("nonexistent.txt")
    print("Failed (Expected)" if not result5 else "Success")
