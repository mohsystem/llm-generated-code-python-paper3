import os
import re
from pathlib import Path

VALID_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def read_file_securely(filename):
    if not filename or not filename.strip():
        return "Error: Filename cannot be null or empty"

    # Validate filename format (no path traversal)
    if '..' in filename or '/' in filename or '\\' in filename:
        return "Error: Invalid filename format - path traversal detected"

    # Validate filename characters
    if not VALID_FILENAME_PATTERN.match(filename):
        return "Error: Filename contains invalid characters"

    try:
        # Get absolute path and validate
        file_path = Path(filename).resolve()
        current_dir = Path('.').resolve()

        # Ensure file is in current directory
        if not str(file_path).startswith(str(current_dir)):
            return "Error: File access outside working directory is not allowed"

        # Check if file exists
        if not file_path.exists():
            return f"Error: File does not exist: {filename}"

        # Check if it's a regular file
        if not file_path.is_file():
            return f"Error: Path is not a regular file: {filename}"

        # Check file size
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return "Error: File size exceeds maximum allowed size"

        # Read file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return content

    except PermissionError:
        return f"Error: Permission denied - cannot read file: {filename}"
    except IOError as e:
        return f"Error: Failed to read file - {str(e)}"
    except Exception as e:
        return f"Error: Unexpected error - {str(e)}"

def main():
    print("=== Test Case 1: Valid file ===")
    try:
        with open("test1.txt", "w") as f:
            f.write("Hello World!\n")
            f.write("This is a test file.\n")
        print(read_file_securely("test1.txt"))
    except Exception as e:
        print("Could not create test file")

    print("\n=== Test Case 2: Non-existent file ===")
    print(read_file_securely("nonexistent.txt"))

    print("\n=== Test Case 3: Path traversal attempt ===")
    print(read_file_securely("../etc/passwd"))

    print("\n=== Test Case 4: Invalid characters ===")
    print(read_file_securely("test@#$.txt"))

    print("\n=== Test Case 5: Null/Empty filename ===")
    print(read_file_securely(None))
    print(read_file_securely(""))

if __name__ == "__main__":
    main()
