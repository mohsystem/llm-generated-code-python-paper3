import os
import sys
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def read_file_content(file_path):
    """
    Securely read and return the content of a file.

    Args:
        file_path: Path to the file to read

    Returns:
        String containing file content or error message
    """
    if not file_path or not isinstance(file_path, str) or not file_path.strip():
        return "Error: File path cannot be null or empty"

    try:
        # Normalize and resolve the path to prevent path traversal
        path = Path(file_path).resolve()

        # Check if file exists
        if not path.exists():
            return f"Error: File does not exist: {file_path}"

        # Check if it's a regular file
        if not path.is_file():
            return f"Error: Path is not a regular file: {file_path}"

        # Check file size to prevent memory exhaustion
        file_size = path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            return "Error: File size exceeds maximum allowed size (10MB)"

        # Read file content securely with UTF-8 encoding
        with open(path, 'r', encoding='utf-8', errors='replace') as file:
            content = file.read()
            return content

    except PermissionError:
        return f"Error: Permission denied to read file: {file_path}"
    except OSError as e:
        return f"Error: Unable to read file - {str(e)}"
    except Exception as e:
        return f"Error: Unexpected error - {str(e)}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python Task70.py <file_path>")
        print("\nRunning test cases...\n")

        # Test case 1: Valid file
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                test_file1 = f.name
                f.write("Hello, World!")
            print("Test 1 - Valid file:")
            print(read_file_content(test_file1))
            os.unlink(test_file1)
        except Exception as e:
            print(f"Test 1 failed: {str(e)}")

        # Test case 2: Non-existent file
        print("\nTest 2 - Non-existent file:")
        print(read_file_content("/nonexistent/file.txt"))

        # Test case 3: None path
        print("\nTest 3 - None path:")
        print(read_file_content(None))

        # Test case 4: Empty path
        print("\nTest 4 - Empty path:")
        print(read_file_content(""))

        # Test case 5: File with special characters
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                test_file5 = f.name
                f.write("Content with special chars: @#$%^&*()")
            print("\nTest 5 - File with special characters:")
            print(read_file_content(test_file5))
            os.unlink(test_file5)
        except Exception as e:
            print(f"Test 5 failed: {str(e)}")
    else:
        file_path = sys.argv[1]
        content = read_file_content(file_path)
        print(content)

if __name__ == "__main__":
    main()
