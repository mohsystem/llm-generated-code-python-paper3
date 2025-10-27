
import zipfile
import os
from pathlib import Path

# Maximum allowed file size: 100 MB to prevent zip bombs
MAX_FILE_SIZE = 100 * 1024 * 1024
# Maximum number of files to prevent excessive resource usage
MAX_FILES = 10000
# Base directory for extraction - must be absolute and validated
BASE_DIR = "/tmp/unpack"

def extract_zip_archive(zip_file_path):
    """\n    Safely extract a zip archive to /tmp/unpack directory.\n    \n    Args:\n        zip_file_path: Path to the zip file to extract\n        \n    Raises:\n        ValueError: If input validation fails\n        IOError: If file operations fail or security checks fail\n    """
    # Validate input path is not None or empty
    if not zip_file_path or not isinstance(zip_file_path, str):
        raise ValueError("Zip file path must be a non-empty string")
    
    # Normalize and validate the base directory
    base_dir = Path(BASE_DIR).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    
    file_count = 0
    total_size = 0
    
    # Open zip file with context manager for automatic cleanup
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        # Iterate through all entries in the zip file
        for entry in zip_ref.infolist():
            file_count += 1
            
            # Prevent zip bomb attacks by limiting file count
            if file_count > MAX_FILES:
                raise IOError(f"Too many files in archive (limit: {MAX_FILES})")
            
            # Get the entry name and validate it
            entry_name = entry.filename
            if not entry_name:
                continue
            
            # Normalize the entry path and resolve against base directory
            target_path = (base_dir / entry_name).resolve()
            
            # Security check: ensure path stays within base directory (prevent directory traversal)
            try:
                target_path.relative_to(base_dir)
            except ValueError:
                raise IOError(f"Entry is outside of the target directory: {entry_name}")
            
            # Handle directories
            if entry.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
            else:
                # Ensure parent directory exists
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Validate file size before extraction to prevent zip bombs
                if entry.file_size > MAX_FILE_SIZE:
                    raise IOError(f"File too large: {entry_name}")
                
                total_size += entry.file_size
                if total_size > MAX_FILE_SIZE * 10:
                    raise IOError("Total extracted size exceeds limit")
                
                # Extract file with additional validation
                # Use read() instead of extract() for better control
                with zip_ref.open(zip_info) as source, open(target_path, "wb") as target:

                    bytes_written = 0
                    chunk_size = 8192
                    
                    while True:
                        chunk = source.read(chunk_size)
                        if not chunk:
                            break
                        
                        bytes_written += len(chunk)
                        
                        # Additional runtime check during extraction
                        if bytes_written > MAX_FILE_SIZE:
                            raise IOError(f"File exceeded size limit during extraction: {entry_name}")
                        
                        target.write(chunk)
                    
                    # Ensure data is written to disk
                    target.flush()
                    os.fsync(target.fileno())
                
                # Set restrictive permissions (owner read/write only)
                os.chmod(target_path, 0o600)

def main():
    """Test cases for zip extraction function"""
    
    # Test case 1: Valid zip file
    try:
        print("Test 1: Extracting valid archive")
        extract_zip_archive("archive.zip")
        print("Test 1 passed")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Non-existent file
    try:
        print("\\nTest 2: Non-existent file")
        extract_zip_archive("nonexistent.zip")
        print("Test 2 failed: should have thrown exception")
    except Exception as e:
        print(f"Test 2 passed: {e}")
    
    # Test case 3: None input
    try:
        print("\\nTest 3: None input")
        extract_zip_archive(None)
        print("Test 3 failed: should have thrown exception")
    except Exception as e:
        print(f"Test 3 passed: {e}")
    
    # Test case 4: Empty string input
    try:
        print("\\nTest 4: Empty string input")
        extract_zip_archive("")
        print("Test 4 failed: should have thrown exception")
    except Exception as e:
        print(f"Test 4 passed: {e}")
    
    # Test case 5: Path with directory traversal attempt
    try:
        print("\\nTest 5: Malicious path (if archive contains traversal)")
        extract_zip_archive("test_traversal.zip")
        print("Test 5: extraction completed with validation")
    except Exception as e:
        print(f"Test 5: {e}")

if __name__ == "__main__":
    main()
