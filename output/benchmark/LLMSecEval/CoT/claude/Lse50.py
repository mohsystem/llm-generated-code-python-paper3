
import zipfile
import os
import pathlib
def secure_extract_zip(zip_file_path, dest_directory):
    """Securely extract zip file to destination directory"""
    # Create destination directory if it doesn't exist
    os.makedirs(dest_directory, exist_ok=True)

    # Get canonical path of destination
    dest_path = pathlib.Path(dest_directory).resolve()

    with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
        for member in zip_ref.namelist():
            # Security: Validate member path
            member_path = (dest_path / member).resolve()

            # Security: Ensure extracted file stays within target directory
            if not str(member_path).startswith(str(dest_path)):
                raise Exception(f"Attempted path traversal in zip file: {member}")

            # Security: Check for absolute paths
            if pathlib.Path(member).is_absolute():
                raise Exception(f"Attempted absolute path in zip file: {member}")

            # Extract the file
            zip_ref.extract(member, dest_directory)

if __name__ == "__main__":
    # Test case 1: Normal extraction
    try:
        secure_extract_zip("archive.zip", "/tmp/unpack")
        print("Test 1: Successfully extracted archive.zip")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: With different archive name
    try:
        secure_extract_zip("test.zip", "/tmp/unpack")
        print("Test 2: Successfully extracted test.zip")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Non-existent file
    try:
        secure_extract_zip("nonexistent.zip", "/tmp/unpack")
        print("Test 3: Completed")
    except Exception as e:
        print(f"Test 3 failed (expected): {e}")
    
    # Test case 4: Different destination
    try:
        secure_extract_zip("archive.zip", "/tmp/unpack2")
        print("Test 4: Successfully extracted to different location")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: Create nested directory structure
    try:
        secure_extract_zip("archive.zip", "/tmp/unpack/nested/path")
        print("Test 5: Successfully extracted to nested path")
    except Exception as e:
        print(f"Test 5 failed: {e}")
