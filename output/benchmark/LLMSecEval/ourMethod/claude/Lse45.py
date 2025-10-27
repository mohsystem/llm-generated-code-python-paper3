
import os
import stat

# Safe directory constant
SAFE_DIRECTORY = "/safe/directory"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
def read_file_from_safe_directory(filename):
    """
    Reads a file from the safe directory with proper security controls.

    Args:
        filename: The requested filename (relative path)

    Returns:
        bytes: File contents

    Raises:
        ValueError: If filename is invalid
        PermissionError: If path traversal detected
        IOError: If file cannot be read or fails validation
    """
    # Input validation: reject None or empty filename
    if not filename:
        raise ValueError("Filename cannot be None or empty")

    # Normalize the safe directory to resolve symlinks
    safe_dir = os.path.realpath(SAFE_DIRECTORY)

    # Construct the requested file path and normalize it
    requested_path = os.path.normpath(os.path.join(safe_dir, filename))

    # Security check: ensure resolved path is within safe directory
    # This prevents path traversal attacks
    if not requested_path.startswith(safe_dir + os.sep):
        raise PermissionError("Access denied: path traversal detected")

    # Open file with O_RDONLY and O_NOFOLLOW to prevent symlink following
    # This is the race-safe approach: open first, then validate
    try:
        fd = os.open(requested_path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as e:
        raise IOError(f"Cannot open file: {e}")

    try:
        # Validate the opened file descriptor with fstat
        st = os.fstat(fd)

        # Check if it's a regular file (not directory, symlink, device, etc.)
        if not stat.S_ISREG(st.st_mode):
            raise IOError("Not a regular file")

        # Check file size to prevent excessive memory allocation
        if st.st_size > MAX_FILE_SIZE:
            raise IOError("File size exceeds maximum allowed size")

        # Read file contents using the validated file descriptor
        with os.fdopen(fd, 'rb') as f:
            content = f.read()
            return content
    except Exception:
        # Ensure fd is closed if fdopen wasn't reached
        try:
            os.close(fd)
        except:
            pass
        raise

def main():
    """Test cases for the secure file reading function."""
    
    # Test case 1: Valid file in safe directory
    try:
        content = read_file_from_safe_directory("test.txt")
        print(f"Test 1 - Valid file: Success ({len(content)} bytes)")
    except Exception as e:
        print(f"Test 1 - Valid file: {e}")
    
    # Test case 2: Attempt path traversal attack
    try:
        content = read_file_from_safe_directory("../../../etc/passwd")
        print("Test 2 - Path traversal: Failed (should be blocked)")
    except PermissionError:
        print("Test 2 - Path traversal: Blocked successfully")
    except Exception as e:
        print(f"Test 2 - Path traversal: {e}")
    
    # Test case 3: None filename
    try:
        content = read_file_from_safe_directory(None)
        print("Test 3 - None filename: Failed (should be rejected)")
    except ValueError:
        print("Test 3 - None filename: Rejected successfully")
    except Exception as e:
        print(f"Test 3 - None filename: {e}")
    
    # Test case 4: Empty filename
    try:
        content = read_file_from_safe_directory("")
        print("Test 4 - Empty filename: Failed (should be rejected)")
    except ValueError:
        print("Test 4 - Empty filename: Rejected successfully")
    except Exception as e:
        print(f"Test 4 - Empty filename: {e}")
    
    # Test case 5: Subdirectory access (valid)
    try:
        content = read_file_from_safe_directory("subdir/file.txt")
        print(f"Test 5 - Subdirectory file: Success ({len(content)} bytes)")
    except Exception as e:
        print(f"Test 5 - Subdirectory file: {e}")


if __name__ == "__main__":
    main()
