
import os
import stat
import tempfile
import os
import stat


class SecurityError(Exception):
    """Custom exception for security-related file errors."""
    pass


# Secure file operation with proper permissions and TOCTOU prevention
def write_to_config_file(base_dir, filename, content):
    """
    Securely write content to a file with restricted permissions.
    Prevents TOCTOU by opening first, then operating on the file descriptor.
    """
    # Security: Validate inputs to prevent path traversal
    if not filename or '..' in filename or '/' in filename or '\\' in filename:
        raise ValueError("Invalid filename")

    if not base_dir:
        raise ValueError("Invalid base directory")

    if content is None:
        raise ValueError("Content cannot be None")

    # Security: Normalize paths and ensure within base directory
    base_path = os.path.abspath(os.path.normpath(base_dir))
    file_path = os.path.abspath(os.path.normpath(os.path.join(base_dir, filename)))

    # Security: Ensure resolved path is within base directory
    if not file_path.startswith(base_path + os.sep) and file_path != base_path:
        raise SecurityError("Path traversal attempt detected")

    # Security: Define restrictive permissions (owner rw, group r, others r) = 0o644
    mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

    fd = None
    try:
        # Security: Open file with O_CREAT, O_WRONLY, O_TRUNC, O_CLOEXEC
        # Set restrictive permissions at creation time (0o644)
        # Prevents TOCTOU by operating directly on the file descriptor
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_CLOEXEC

        # Add O_NOFOLLOW where available to prevent symlink following
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW

        # Security: Open with restrictive permissions atomically
        fd = os.open(file_path, flags, mode)

        # Security: Validate the opened file descriptor
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecurityError("Not a regular file")

        # Security: Write using the opened file descriptor (no TOCTOU)
        content_bytes = content.encode('utf-8')
        bytes_written = 0
        while bytes_written < len(content_bytes):
            written = os.write(fd, content_bytes[bytes_written:])
            if written <= 0:
                raise IOError("Write failed")
            bytes_written += written

        # Security: Force write to disk
        os.fsync(fd)

    finally:
        # Security: Always close the file descriptor
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass  # Avoid masking the original exception

# Test cases
if __name__ == "__main__":
    base_dir = tempfile.gettempdir()
    
    # Test case 1: Basic write
    try:
        write_to_config_file(base_dir, "important_config", "important_config")
        print("Test 1 passed: Basic write successful")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Write with different content
    try:
        write_to_config_file(base_dir, "test_config2", "test_data_123")
        print("Test 2 passed: Different content write successful")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Empty content
    try:
        write_to_config_file(base_dir, "empty_config", "")
        print("Test 3 passed: Empty content write successful")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Path traversal attempt (should fail)
    try:
        write_to_config_file(base_dir, "../etc/passwd", "malicious")
        print("Test 4 failed: Path traversal not blocked")
    except (ValueError, SecurityError):
        print("Test 4 passed: Path traversal blocked")
    except Exception as e:
        print(f"Test 4 failed with unexpected error: {e}")
    
    # Test case 5: Null/invalid filename (should fail)
    try:
        write_to_config_file(base_dir, "", "content")
        print("Test 5 failed: Empty filename not rejected")
    except ValueError:
        print("Test 5 passed: Empty filename rejected")
    except Exception as e:
        print(f"Test 5 failed with unexpected error: {e}")


class SecurityError(Exception):
    """Custom exception for security violations"""
    pass
