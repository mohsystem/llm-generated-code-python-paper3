
import zipfile
import os

import os
import zipfile

def unzip_archive(zip_file_path, dest_directory):
    """
    Securely unzips a ZIP archive to the specified destination directory.
    Prevents path traversal attacks by validating extracted file paths.
    """
    os.makedirs(dest_directory, exist_ok=True)
    dest_path = os.path.abspath(dest_directory)

    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # Security check: prevent path traversal attacks
            member_path = os.path.abspath(os.path.join(dest_directory, member))
            if not member_path.startswith(dest_path):
                raise Exception(f"Attempted path traversal in zip file: {member}")

        # Safe extraction after validation
        zip_ref.extractall(dest_directory)

def main():
    # Test case 1: Basic unzip
    try:
        unzip_archive("archive.zip", "/tmp/unpack")
        print("Test 1: Successfully unzipped to /tmp/unpack")
    except Exception as e:
        print(f"Test 1 Error: {e}")
    
    # Test case 2: Different destination
    try:
        unzip_archive("archive.zip", "/tmp/unpack2")
        print("Test 2: Successfully unzipped to /tmp/unpack2")
    except Exception as e:
        print(f"Test 2 Error: {e}")
    
    # Test case 3: Unzip to existing directory
    try:
        unzip_archive("archive.zip", "/tmp/unpack")
        print("Test 3: Successfully unzipped to existing directory")
    except Exception as e:
        print(f"Test 3 Error: {e}")
    
    # Test case 4: Create nested directories
    try:
        unzip_archive("archive.zip", "/tmp/test/nested/unpack")
        print("Test 4: Successfully created nested directories")
    except Exception as e:
        print(f"Test 4 Error: {e}")
    
    # Test case 5: Handle non-existent zip file
    try:
        unzip_archive("nonexistent.zip", "/tmp/unpack")
        print("Test 5: Should have thrown exception")
    except FileNotFoundError:
        print("Test 5: Correctly handled non-existent file")
    except Exception as e:
        print(f"Test 5 Error: {e}")

if __name__ == "__main__":
    main()
