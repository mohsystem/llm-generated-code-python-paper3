import os
import re
from pathlib import Path

SAFE_DIRECTORY = "safe_files"
ALLOWED_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".xml"}

def retrieve_file(file_name):
    """
    Securely retrieve file content from the safe directory.

    Args:
        file_name: Name of the file to retrieve

    Returns:
        String containing file content or error message
    """
    try:
        # Input validation
        if not file_name or not file_name.strip():
            return "Error: File name cannot be empty"

        # Remove path traversal attempts
        file_name = file_name.replace("..", "").replace("/", "").replace("\\", "")

        # Validate file extension
        if not is_allowed_extension(file_name):
            return "Error: File extension not allowed"

        # Create safe directory if it doesn't exist
        safe_dir = Path(SAFE_DIRECTORY)
        safe_dir.mkdir(exist_ok=True)

        # Build safe file path
        base_path = safe_dir.resolve()
        file_path = (base_path / file_name).resolve()

        # Verify the file is within the safe directory (prevent path traversal)
        if not str(file_path).startswith(str(base_path)):
            return "Error: Access denied - path traversal detected"

        # Check if file exists
        if not file_path.is_file():
            return "Error: File not found"

        # Check file size (10MB limit)
        if file_path.stat().st_size > 10 * 1024 * 1024:
            return "Error: File too large"

        # Read file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return f"Success: File retrieved\n{content}"

    except Exception as e:
        return f"Error: {str(e)}"


def is_allowed_extension(file_name):
    """Check if file has an allowed extension."""
    return any(file_name.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)


def setup_test_files():
    """Create test files for demonstration."""
    try:
        safe_dir = Path(SAFE_DIRECTORY)
        safe_dir.mkdir(exist_ok=True)

        test_file = safe_dir / "test1.txt"
        with open(test_file, 'w') as f:
            f.write(
                "This is a test file content.\n"
                "Secure file retrieval system."
            )
    except Exception as e:
        print(f"Setup error: {e}")


if __name__ == "__main__":
    # Create test files
    setup_test_files()

    # Test Case 1: Valid file retrieval
    print("Test 1 - Valid file:")
    print(retrieve_file("test1.txt"))

    # Test Case 2: Path traversal attempt
    print("\nTest 2 - Path traversal attempt:")
    print(retrieve_file("../../../etc/passwd"))

    # Test Case 3: Invalid extension
    print("\nTest 3 - Invalid extension:")
    print(retrieve_file("malicious.exe"))

    # Test Case 4: Empty filename
    print("\nTest 4 - Empty filename:")
    print(retrieve_file(""))

    # Test Case 5: Non-existent file
    print("\nTest 5 - Non-existent file:")
    print(retrieve_file("nonexistent.txt"))
