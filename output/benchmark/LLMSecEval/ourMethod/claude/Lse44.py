
import os
from pathlib import Path

SAFE_DIR = "/safe/"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
def read_safe_file(filename):
    """
    Reads a file from the /safe/ directory with path traversal protection.

    Args:
        filename: The requested filename (relative path within /safe/)

    Returns:
        bytes: File contents, or None on error
    """
    if not filename or not isinstance(filename, str):
        print("Error: Invalid filename", file=__import__('sys').stderr)
        return None

    try:
        # Normalize and resolve the base directory
        base_dir = Path(SAFE_DIR).resolve()

        # Resolve the requested file against the base directory
        requested_path = (base_dir / filename).resolve()

        # Verify the resolved path is within the base directory
        if not str(requested_path).startswith(str(base_dir)):
            print("Error: Path traversal attempt detected", file=__import__('sys').stderr)
            return None

        # Open file with O_RDONLY and no symlink following, then validate
        fd = os.open(str(requested_path), os.O_RDONLY | os.O_CLOEXEC)

        try:
            # Validate the opened file descriptor
            stat_info = os.fstat(fd)

            # Check if it's a regular file
            if not __import__('stat').S_ISREG(stat_info.st_mode):
                print("Error: Not a regular file", file=__import__('sys').stderr)
                return None

            # Check file size
            if stat_info.st_size > MAX_FILE_SIZE:
                print("Error: File size exceeds limit", file=__import__('sys').stderr)
                return None

            # Read from the file descriptor
            with os.fdopen(fd, 'rb') as f:
                fd = -1  # Prevent double close
                return f.read()

        finally:
            if fd >= 0:
                os.close(fd)

    except FileNotFoundError:
        print("Error: File does not exist", file=__import__('sys').stderr)
        return None
    except OSError:
        print("Error: Unable to read file", file=__import__('sys').stderr)
        return None


def main():
    # Test case 1: Valid file in safe directory
    print("Test 1 - Valid file:")
    result1 = read_safe_file("test.txt")
    print(f"Success: Read {len(result1)} bytes" if result1 else "Failed")
    
    # Test case 2: Path traversal attempt with ../
    print("\\nTest 2 - Path traversal attempt:")
    result2 = read_safe_file("../etc/passwd")
    print("SECURITY BREACH" if result2 else "Blocked as expected")
    
    # Test case 3: Absolute path attempt
    print("\\nTest 3 - Absolute path attempt:")
    result3 = read_safe_file("/etc/passwd")
    print("SECURITY BREACH" if result3 else "Blocked as expected")
    
    # Test case 4: None filename
    print("\\nTest 4 - None filename:")
    result4 = read_safe_file(None)
    print("Unexpected success" if result4 else "Handled correctly")
    
    # Test case 5: Empty filename
    print("\\nTest 5 - Empty filename:")
    result5 = read_safe_file("")
    print("Unexpected success" if result5 else "Handled correctly")


if __name__ == "__main__":
    main()
