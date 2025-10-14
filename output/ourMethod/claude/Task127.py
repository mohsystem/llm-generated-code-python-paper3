
import os
import tempfile
import pathlib
from typing import Optional


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
BUFFER_SIZE = 8192


def copy_file_to_temp(base_dir: str, relative_file_path: str) -> str:
    if not base_dir or not base_dir.strip():
        raise ValueError("Base directory cannot be None or empty")
    if not relative_file_path or not relative_file_path.strip():
        raise ValueError("Relative file path cannot be None or empty")

    base_path = pathlib.Path(base_dir).resolve()
    if not base_path.exists() or not base_path.is_dir():
        raise ValueError("Base directory does not exist or is not a directory")

    target_path = (base_path / relative_file_path).resolve()
    
    try:
        target_path.relative_to(base_path)
    except ValueError:
        raise SecurityError("Path traversal attempt detected")

    if not target_path.exists():
        raise FileNotFoundError(f"Source file does not exist: {target_path}")
    
    if not target_path.is_file() or target_path.is_symlink():
        raise ValueError("Source path is not a regular file or is a symlink")
    
    if not os.access(target_path, os.R_OK):
        raise IOError("Source file is not readable")

    file_size = target_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise IOError("File size exceeds maximum allowed size")

    temp_fd = None
    temp_path = None
    
    try:
        temp_fd, temp_path = tempfile.mkstemp(prefix="secure_copy_", suffix=".tmp")
        os.chmod(temp_path, 0o600)
        
        with os.fdopen(temp_fd, 'wb') as temp_file:
            temp_fd = None
            
            with open(target_path, 'rb') as source_file:
                total_bytes_read = 0
                
                while True:
                    chunk = source_file.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    
                    total_bytes_read += len(chunk)
                    if total_bytes_read > MAX_FILE_SIZE:
                        raise IOError("File size check failed during copy")
                    
                    temp_file.write(chunk)
            
            temp_file.flush()
            os.fsync(temp_file.fileno())
        
        return temp_path
        
    except Exception as e:
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except:
                pass
        
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass
        
        raise IOError(f"Failed to copy file: {str(e)}") from e


class SecurityError(Exception):
    pass


def main():
    test_base_dir = tempfile.gettempdir()
    
    # Test Case 1: Valid file copy
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=test_base_dir, 
                                        prefix='test1_', suffix='.txt') as f:
            test_file1 = f.name
            f.write("Test content 1")
        
        result1 = copy_file_to_temp(test_base_dir, os.path.basename(test_file1))
        print(f"Test 1 PASS: {result1}")
        
        os.unlink(test_file1)
        os.unlink(result1)
    except Exception as e:
        print(f"Test 1 FAIL: {e}")
    
    # Test Case 2: None base directory
    try:
        copy_file_to_temp(None, "test.txt")
        print("Test 2 FAIL: Should throw exception")
    except ValueError as e:
        print(f"Test 2 PASS: {e}")
    except Exception as e:
        print(f"Test 2 FAIL: Wrong exception type - {e}")
    
    # Test Case 3: Path traversal attempt
    try:
        copy_file_to_temp(test_base_dir, "../etc/passwd")
        print("Test 3 FAIL: Should throw exception")
    except (SecurityError, ValueError) as e:
        print(f"Test 3 PASS: {e}")
    except Exception as e:
        print(f"Test 3 PASS: Path traversal blocked - {e}")
    
    # Test Case 4: Non-existent file
    try:
        copy_file_to_temp(test_base_dir, "nonexistent_file_12345.txt")
        print("Test 4 FAIL: Should throw exception")
    except FileNotFoundError as e:
        print(f"Test 4 PASS: {e}")
    except Exception as e:
        print(f"Test 4 FAIL: Wrong exception type - {e}")
    
    # Test Case 5: Empty file path
    try:
        copy_file_to_temp(test_base_dir, "")
        print("Test 5 FAIL: Should throw exception")
    except ValueError as e:
        print(f"Test 5 PASS: {e}")
    except Exception as e:
        print(f"Test 5 FAIL: Wrong exception type - {e}")


if __name__ == "__main__":
    main()
