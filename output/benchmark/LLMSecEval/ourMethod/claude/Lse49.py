
import os
import zipfile
from pathlib import Path

# Maximum file size to prevent zip bomb attacks (100MB)
MAX_FILE_SIZE = 100 * 1024 * 1024
# Maximum total extracted size (500MB)
MAX_TOTAL_SIZE = 500 * 1024 * 1024
# Maximum number of files to prevent resource exhaustion
MAX_FILE_COUNT = 10000
# Base directory for extraction
BASE_DIR = "/tmp/unpack"

def unzip_archive(zip_file_path):
    """\n    Safely extract a zip archive to /tmp/unpack directory.\n    \n    Args:\n        zip_file_path: Path to the zip file to extract\n        \n    Raises:\n        ValueError: If input is invalid\n        IOError: If extraction fails or security limits are exceeded\n    """
    # Validate input
    if not zip_file_path:
        raise ValueError("Zip file path cannot be empty or None")
    
    # Create and normalize base directory
    base_dir = Path(BASE_DIR).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    
    total_size = 0
    file_count = 0
    
    # Open and extract zip file safely
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            # Get list of all files in archive
            for zip_info in zip_ref.infolist():
                file_count += 1
                if file_count > MAX_FILE_COUNT:
                    raise IOError("Too many files in archive - potential zip bomb")
                
                # Get and validate entry name
                entry_name = zip_info.filename
                if not entry_name:
                    continue
                
                # Resolve target path and normalize
                target_path = (base_dir / entry_name).resolve()
                
                # Security: Ensure the resolved path is within the base directory
                # This prevents path traversal attacks (e.g., ../../etc/passwd)
                try:
                    target_path.relative_to(base_dir)
                except ValueError:
                    raise IOError(f"Path traversal attempt detected: {entry_name}")
                
                # Handle directories
                if zip_info.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue
                
                # Create parent directories for files
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Extract file with size validation
                entry_size = 0
                # Use read() instead of extract() for better control
                with zip_ref.open(zip_info) as source, open(target_path, "wb") as target:
                    while True:
                        chunk = source.read(8192)
                        if not chunk:
                            break
                        
                        chunk_size = len(chunk)
                        entry_size += chunk_size
                        total_size += chunk_size
                        
                        # Check individual file size to prevent zip bombs
                        if entry_size > MAX_FILE_SIZE:
                            raise IOError(f"File too large - potential zip bomb: {entry_name}")
                        
                        # Check total extracted size to prevent zip bombs
                        if total_size > MAX_TOTAL_SIZE:
                            raise IOError("Total extracted size exceeds limit - potential zip bomb")
                        
                        target.write(chunk)
                
    except zipfile.BadZipFile as e:
        raise IOError(f"Invalid or corrupted zip file: {str(e)}")
    except FileNotFoundError as e:
        raise IOError(f"Zip file not found: {str(e)}")


def main():
    """Test cases for unzip_archive function."""
    
    # Test case 1: Valid zip file extraction
    try:
        print("Test 1: Extracting valid archive")
        unzip_archive("archive.zip")
        print("Test 1: SUCCESS")
    except Exception as e:
        print(f"Test 1: FAILED - {str(e)}")
    
    # Test case 2: Non-existent file
    try:
        print("\\nTest 2: Non-existent file")
        unzip_archive("nonexistent.zip")
        print("Test 2: FAILED - Should have thrown exception")
    except Exception as e:
        print(f"Test 2: SUCCESS - Caught expected exception: {str(e)}")
    
    # Test case 3: None input
    try:
        print("\\nTest 3: None input")
        unzip_archive(None)
        print("Test 3: FAILED - Should have thrown exception")
    except Exception as e:
        print(f"Test 3: SUCCESS - Caught expected exception: {str(e)}")
    
    # Test case 4: Empty string input
    try:
        print("\\nTest 4: Empty string input")
        unzip_archive("")
        print("Test 4: FAILED - Should have thrown exception")
    except Exception as e:
        print(f"Test 4: SUCCESS - Caught expected exception: {str(e)}")
    
    # Test case 5: Archive with special name
    try:
        print("\\nTest 5: Archive with special name")
        unzip_archive("test-archive_v1.0.zip")
        print("Test 5: SUCCESS")
    except Exception as e:
        print(f"Test 5: FAILED - {str(e)}")


if __name__ == "__main__":
    main()
