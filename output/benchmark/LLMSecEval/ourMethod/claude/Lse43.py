import os
import sys
from pathlib import Path

# Maximum file size limit (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024
BASE_DIR = "/safe/"


def read_safe_file(filename):
    """
    Securely reads a file from /safe/ directory

    Args:
        filename: The name of the file to read (relative to /safe/)

    Returns:
        File contents as string, or None on error
    """
    # Input validation - reject None or empty
    if not filename or not filename.strip():
        print("Invalid filename", file=sys.stderr)
        return None

    # Reject obvious traversal attempts
    if ".." in filename or "/" in filename or "\\" in filename:
        print("Invalid filename characters", file=sys.stderr)
        return None

    try:
        # Construct and normalize paths
        base_path = Path(BASE_DIR).resolve()
        file_path = (base_path / filename).resolve()

        # Verify resolved path is within base directory (path traversal check)
        if not str(file_path).startswith(str(base_path)):
            print("Path traversal detected", file=sys.stderr)
            return None

        # Open file with O_NOFOLLOW to prevent symlink following
        # Use os.open for low-level control
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = os.open(str(file_path), flags)

        try:
            # Validate file descriptor - must be regular file
            stat_info = os.fstat(fd)

            # Check if regular file
            import stat as stat_module

            if not stat_module.S_ISREG(stat_info.st_mode):
                print("Not a regular file", file=sys.stderr)
                os.close(fd)
                return None

            # Check size limit
            if stat_info.st_size > MAX_FILE_SIZE:
                print("File too large", file=sys.stderr)
                os.close(fd)
                return None

            # Read file using the validated descriptor
            with os.fdopen(fd, "rb") as f:
                content = f.read()
                return content.decode("utf-8")

        except Exception:
            os.close(fd)
            raise

    except FileNotFoundError:
        print("File not found", file=sys.stderr)
        return None
    except PermissionError:
        print("Permission denied", file=sys.stderr)
        return None
    except Exception:
        print("File operation failed", file=sys.stderr)
        return None


def main():
    # Test case 1: Valid file
    print("Test 1: Valid file")
    result1 = read_safe_file("test.txt")
    print(f"Result: {'Success' if result1 is not None else 'Failed'}")

    # Test case 2: Path traversal attempt
    print("\nTest 2: Path traversal with ..")
    result2 = read_safe_file("../etc/passwd")
    print(f"Result: {'Blocked' if result2 is None else 'Failed'}")

    # Test case 3: Absolute path attempt
    print("\nTest 3: Absolute path")
    result3 = read_safe_file("/etc/passwd")
    print(f"Result: {'Blocked' if result3 is None else 'Failed'}")

    # Test case 4: None input
    print("\nTest 4: None input")
    result4 = read_safe_file(None)
    print(f"Result: {'Blocked' if result4 is None else 'Failed'}")

    # Test case 5: Empty filename
    print("\nTest 5: Empty filename")
    result5 = read_safe_file("")
    print(f"Result: {'Blocked' if result5 is None else 'Failed'}")


if __name__ == "__main__":
    main()
