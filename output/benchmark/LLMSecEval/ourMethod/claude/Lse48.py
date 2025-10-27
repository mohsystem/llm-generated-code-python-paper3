
import os
from pathlib import Path
from typing import Optional

# Secure base directory for serving images - must be set to a trusted directory
BASE_DIR = Path("./images").resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
def img(file_param: Optional[str]) -> bytes:
    """
    Securely read and return image file content.

    Args:
        file_param: The requested file path (relative to BASE_DIR)

    Returns:
        bytes: The file content

    Raises:
        ValueError: If file_param is invalid
        PermissionError: If path traversal is attempted
        FileNotFoundError: If file doesn't exist
        IOError: If file is too large or not a regular file
    """
    # Input validation: reject None or empty file parameter
    if not file_param or not file_param.strip():
        raise ValueError("File parameter is required")

    # Normalize and resolve the requested path against the base directory
    # This prevents path traversal attacks
    requested_path = (BASE_DIR / file_param).resolve()

    # Security check: ensure the resolved path is within BASE_DIR
    # This prevents directory traversal attacks like ../../../etc/passwd
    if not str(requested_path).startswith(str(BASE_DIR)):
        raise PermissionError("Access denied: path traversal attempt detected")

    # Open the file with secure flags - no symlink following
    # Use os.open with O_RDONLY and O_NOFOLLOW to prevent symlink attacks
    try:
        # Check if path exists without following symlinks
        if not requested_path.exists():
            raise FileNotFoundError("File not found")

        # Validate that it's a regular file (not a directory or symlink)
        if not requested_path.is_file():
            raise PermissionError("Access denied: not a regular file")

        # Check for symlinks explicitly
        if requested_path.is_symlink():
            raise PermissionError("Access denied: symbolic links not allowed")

        # Check file size before reading to prevent memory exhaustion
        file_size = requested_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise IOError("File too large")

        # Open file descriptor with secure flags
        fd = os.open(
            requested_path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )

        try:
            # Validate the opened file descriptor
            stat_info = os.fstat(fd)
            if not stat_info.st_mode & 0o100000:  # S_IFREG check
                raise PermissionError("Access denied: not a regular file")

            # Read file content using the validated file descriptor
            with os.fdopen(fd, "rb") as f:
                file_content = f.read()

            return file_content
        except Exception:
            os.close(fd)
            raise

    except (OSError, IOError) as e:
        raise IOError(f"Error reading file: {str(e)}")


def main():
    """Test cases for the img function"""
    # Create base directory if it doesn't exist
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    print("Test Case 1: Valid image file")
    try:
        # Create a test file
        test_file1 = BASE_DIR / "test1.jpg"
        test_file1.write_bytes(b'\\xFF\\xD8\\xFF\\xE0')
        result1 = img("test1.jpg")
        print(f"Success: Read {len(result1)} bytes")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\\nTest Case 2: Path traversal attempt (should fail)")
    try:
        result2 = img("../../../etc/passwd")
        print("Error: Should have been blocked")
    except PermissionError as e:
        print(f"Success: {e}")
    
    print("\\nTest Case 3: None file parameter (should fail)")
    try:
        result3 = img(None)
        print("Error: Should have been blocked")
    except ValueError as e:
        print(f"Success: {e}")
    
    print("\\nTest Case 4: Non-existent file (should fail)")
    try:
        result4 = img("nonexistent.jpg")
        print("Error: Should have failed")
    except (FileNotFoundError, IOError) as e:
        print(f"Success: {e}")
    
    print("\\nTest Case 5: Empty filename (should fail)")
    try:
        result5 = img("")
        print("Error: Should have been blocked")
    except ValueError as e:
        print(f"Success: {e}")

if __name__ == "__main__":
    main()
