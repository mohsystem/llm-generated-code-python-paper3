
import os
import stat
import tempfile
from typing import Optional

def open_file_create(base_dir: str, filename: str) -> int:
    """\n    Open/create file with O_CREAT|O_WRONLY|O_TRUNC flags\n    Returns file descriptor for writing\n    Security: validates paths, prevents traversal, uses restrictive permissions\n    """
    # Validate inputs - reject None or empty
    if not base_dir or not filename:
        raise ValueError("Base directory and filename must not be empty")
    
    # Security: reject if filename contains path separators
    if os.sep in filename or (os.altsep and os.altsep in filename):
        raise ValueError("Filename must not contain path separators")
    
    # Normalize paths to prevent traversal
    base_path = os.path.abspath(os.path.normpath(base_dir))
    file_path = os.path.abspath(os.path.normpath(os.path.join(base_path, filename)))
    
    # Security: ensure resolved path is within base directory
    if not file_path.startswith(base_path + os.sep) and file_path != base_path:
        raise SecurityError("Path traversal attempt detected")
    
    # Ensure base directory exists
    if not os.path.isdir(base_path):
        raise IOError("Base directory does not exist")
    
    # O_CREAT|O_WRONLY|O_TRUNC with O_NOFOLLOW to prevent symlink following
    # Security: use restrictive permissions 0600 at creation time
    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_CLOEXEC
    
    # Add O_NOFOLLOW if available to prevent symlink following
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    
    try:
        # Open with restrictive permissions (0600 - owner read/write only)
        fd = os.open(file_path, flags, mode=0o600)
        
        # Validate the opened file descriptor
        st = os.fstat(fd)
        
        # Security: ensure it's a regular file\n        if not stat.S_ISREG(st.st_mode):\n            os.close(fd)\n            raise IOError("Not a regular file")\n        \n        return fd\n    except OSError as e:\n        raise IOError(f"Failed to open file: {e}")\n\n\ndef open_file_create_exclusive(base_dir: str, filename: str) -> int:\n    """\n    Open/create file with O_CREAT|O_WRONLY|O_EXCL flags\n    Returns file descriptor, fails if file already exists\n    Security: validates paths, prevents traversal, uses restrictive permissions\n    """\n    # Validate inputs\n    if not base_dir or not filename:\n        raise ValueError("Base directory and filename must not be empty")\n    \n    # Security: reject if filename contains path separators\n    if os.sep in filename or (os.altsep and os.altsep in filename):\n        raise ValueError("Filename must not contain path separators")\n    \n    # Normalize paths\n    base_path = os.path.abspath(os.path.normpath(base_dir))\n    file_path = os.path.abspath(os.path.normpath(os.path.join(base_path, filename)))\n    \n    # Security: ensure resolved path is within base directory\n    if not file_path.startswith(base_path + os.sep) and file_path != base_path:\n        raise SecurityError("Path traversal attempt detected")\n    \n    # Ensure base directory exists\n    if not os.path.isdir(base_path):\n        raise IOError("Base directory does not exist")\n    \n    # O_CREAT|O_WRONLY|O_EXCL with O_NOFOLLOW\n    # Security: use restrictive permissions 0600 at creation time\n    flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_CLOEXEC\n    \n    # Add O_NOFOLLOW if available\n    if hasattr(os, 'O_NOFOLLOW'):\n        flags |= os.O_NOFOLLOW\n    \n    try:\n        # Open with exclusive creation (fails if exists) and restrictive permissions\n        fd = os.open(file_path, flags, mode=0o600)\n        \n        # Validate the opened file descriptor\n        st = os.fstat(fd)\n        \n        # Security: ensure it's a regular file
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise IOError("Not a regular file")
        
        return fd
    except OSError as e:
        raise IOError(f"Failed to create file (may already exist): {e}")


# Custom exception for security errors
class SecurityError(Exception):
    pass


def main():
    """Test cases demonstrating secure file operations"""
    test_dir = tempfile.gettempdir()
    
    # Test case 1: Create or truncate file
    print("Test 1: Create/truncate file")
    try:
        fd = open_file_create(test_dir, "test1.txt")
        os.write(fd, b"Test data\\n")
        os.close(fd)
        print("Success: File created/truncated")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 2: Create exclusive file (should succeed first time)
    print("\\nTest 2: Create exclusive file")
    try:
        fd = open_file_create_exclusive(test_dir, "test2.txt")
        os.write(fd, b"Exclusive data\\n")
        os.close(fd)
        print("Success: Exclusive file created")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 3: Create exclusive file again (should fail)
    print("\\nTest 3: Create exclusive file that exists (should fail)")
    try:
        fd = open_file_create_exclusive(test_dir, "test2.txt")
        os.close(fd)
        print("Success: Exclusive file created")
    except Exception as e:
        print(f"Expected error: {e}")
    
    # Test case 4: Path traversal attempt (should fail)
    print("\\nTest 4: Path traversal attempt (should fail)")
    try:
        fd = open_file_create(test_dir, "../etc/passwd")
        os.close(fd)
        print("Success: File created")
    except Exception as e:
        print(f"Expected error: {e}")
    
    # Test case 5: Invalid input (should fail)
    print("\\nTest 5: Invalid empty filename (should fail)")
    try:
        fd = open_file_create(test_dir, "")
        os.close(fd)
        print("Success: File created")
    except Exception as e:
        print(f"Expected error: {e}")
    
    # Cleanup
    try:
        os.unlink(os.path.join(test_dir, "test1.txt"))
    except OSError:
        pass
    try:
        os.unlink(os.path.join(test_dir, "test2.txt"))
    except OSError:
        pass


if __name__ == "__main__":
    main()
