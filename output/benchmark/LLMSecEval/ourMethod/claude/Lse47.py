import os
from pathlib import Path

BASE_DIR = "images"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit


def validate_and_resolve_path(filename):
    """
    Validates and safely resolves a file path within the base directory.
    Returns None if the path is invalid or outside the base directory.
    """
    if not filename or not isinstance(filename, str):
        return None

    # Reject path traversal patterns
    if ".." in filename or "/" in filename or "\\" in filename:
        return None

    try:
        # Get absolute path of base directory
        base_path = Path(BASE_DIR).resolve()

        # Resolve the requested path
        requested_path = (base_path / filename).resolve()

        # Ensure the resolved path is within the base directory
        if not str(requested_path).startswith(str(base_path)):
            return None

        return requested_path
    except (OSError, ValueError):
        return None


def serve_image(filename):
    """
    Handles image file requests with secure path validation.
    This would typically be a route handler in a web framework.
    """
    file_path = validate_and_resolve_path(filename)

    if file_path is None:
        return None

    try:
        # Open the file with O_RDONLY and O_NOFOLLOW to prevent symlink following
        fd = os.open(file_path, os.O_RDONLY | os.O_CLOEXEC)

        # Validate the opened file descriptor
        stat_info = os.fstat(fd)

        # Check if it's a regular file (not directory or symlink)
        import stat
        if not stat.S_ISREG(stat_info.st_mode):
            os.close(fd)
            return None

        # Check file size
        if stat_info.st_size > MAX_FILE_SIZE:
            os.close(fd)
            return None

        # Read file using the validated file descriptor
        with os.fdopen(fd, "rb") as f:
            content = f.read()

        return content
    except (OSError, IOError):
        return None


def main():
    """Test cases for the serve_image function"""
    # Create images directory if it doesn't exist
    os.makedirs(BASE_DIR, exist_ok=True)

    # Test case setup - create test files
    try:
        with open(os.path.join(BASE_DIR, "test1.jpg"), "wb") as f:
            f.write(b"test image 1")
        with open(os.path.join(BASE_DIR, "test2.png"), "wb") as f:
            f.write(b"test image 2")
        with open(os.path.join(BASE_DIR, "valid.gif"), "wb") as f:
            f.write(b"test image 3")
    except IOError:
        print("Failed to create test files")

    # Test cases
    print("Test 1 - Valid file:")
    result1 = serve_image("test1.jpg")
    print("SUCCESS - File served" if result1 is not None else "FAILED")

    print("\nTest 2 - Another valid file:")
    result2 = serve_image("test2.png")
    print("SUCCESS - File served" if result2 is not None else "FAILED")

    print("\nTest 3 - Non-existent file:")
    result3 = serve_image("nonexistent.jpg")
    print("SUCCESS - Rejected" if result3 is None else "FAILED")

    print("\nTest 4 - Path traversal attempt:")
    result4 = serve_image("../etc/passwd")
    print("SUCCESS - Rejected" if result4 is None else "FAILED")

    print("\nTest 5 - Path with slash:")
    result5 = serve_image("subdir/file.jpg")
    print("SUCCESS - Rejected" if result5 is None else "FAILED")


if __name__ == "__main__":
    main()
