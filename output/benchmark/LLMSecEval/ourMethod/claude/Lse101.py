
import os
import tempfile
import stat
from pathlib import Path

# Security: Define base directory to prevent path traversal
BASE_DIR = Path.home() / "app_data"

def write_config(filename, content):
    """\n    Writes content to a file with secure permissions and atomic operation.\n    \n    Args:\n        filename: Name of the file to write\n        content: Content to write to the file\n    \n    Raises:\n        ValueError: If filename or content is invalid\n        PermissionError: If unable to set proper permissions\n    """
    # Security: Validate input parameters
    if not filename or not isinstance(filename, str) or not filename.strip():
        raise ValueError("Filename must be a non-empty string")
    if content is None:
        raise ValueError("Content cannot be None")
    
    # Security: Ensure base directory exists with restrictive permissions
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        # Set directory permissions: owner rwx only (0o700)
        os.chmod(BASE_DIR, stat.S_IRWXU)
    except Exception as e:
        raise PermissionError(f"Failed to set directory permissions: {e}")
    
    # Security: Normalize and validate path to prevent traversal
    target_path = (BASE_DIR / filename).resolve()
    if not str(target_path).startswith(str(BASE_DIR.resolve())):
        raise ValueError("Path traversal attempt detected")
    
    # Security: Use temporary file with restrictive permissions for atomic write
    # Create temp file in same directory as target for atomic rename
    fd = None
    temp_path = None
    
    try:
        # Security: Create temp file with owner-only read/write (0o600)
        fd = os.open(
            BASE_DIR,
            os.O_RDONLY | os.O_DIRECTORY
        )
        
        # Create temp file using low-level API for security
        temp_fd = tempfile.mkstemp(
            dir=BASE_DIR,
            prefix=".tmp_",
            suffix="_config"
        )
        temp_path = Path(temp_fd[1])
        
        # Security: Set restrictive permissions immediately (owner read/write only)
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
        
        # Security: Write using context manager for automatic cleanup
        with os.fdopen(temp_fd[0], 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())  # Ensure data is written to disk
        
        # Security: Atomic rename to prevent partial writes or TOCTOU
        os.replace(temp_path, target_path)
        
        # Security: Set final file permissions (owner read/write only)
        os.chmod(target_path, stat.S_IRUSR | stat.S_IWUSR)
        
    except Exception as e:
        # Security: Clean up temp file on failure
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except:
                pass  # Best effort cleanup
        raise
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except:
                pass

if __name__ == "__main__":
    # Test case 1: Normal write operation
    try:
        write_config("important_config", "important_config")
        print("Test 1 passed: File written successfully")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Write with different content
    try:
        write_config("important_config", "test_content_123")
        print("Test 2 passed: File updated successfully")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Invalid filename (empty)
    try:
        write_config("", "content")
        print("Test 3 failed: Should have raised ValueError")
    except ValueError:
        print("Test 3 passed: Empty filename rejected")
    except Exception as e:
        print(f"Test 3 failed with unexpected exception: {e}")
    
    # Test case 4: Path traversal attempt
    try:
        write_config("../../../etc/passwd", "malicious")
        print("Test 4 failed: Path traversal not blocked")
    except ValueError as e:
        print("Test 4 passed: Path traversal blocked")
    except Exception as e:
        print(f"Test 4 failed with unexpected exception: {e}")
    
    # Test case 5: None content
    try:
        write_config("test_config", None)
        print("Test 5 failed: None content should be rejected")
    except ValueError:
        print("Test 5 passed: None content rejected")
    except Exception as e:
        print(f"Test 5 failed with unexpected exception: {e}")
