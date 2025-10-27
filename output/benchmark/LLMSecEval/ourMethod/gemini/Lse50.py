import os
import zipfile
import shutil

def extract_archive(zip_file_path: str, dest_dir_path: str) -> bool:
    """
    Extracts a zip archive to a destination directory, preventing path traversal.

    Args:
        zip_file_path: The path to the zip file.
        dest_dir_path: The directory to extract files into.

    Returns:
        True if successful, False otherwise.
    """
    if not os.path.exists(zip_file_path):
        print(f"Error: ZIP file not found at {zip_file_path}")
        return False

    try:
        # Get the real, absolute path of the destination directory
        dest_dir_abs = os.path.realpath(dest_dir_path)
        os.makedirs(dest_dir_abs, exist_ok=True)

        with zipfile.ZipFile(zip_file_path, 'r') as zf:
            for member_info in zf.infolist():
                member_name = member_info.filename
                
                # Create the full destination path for the member
                dest_path = os.path.join(dest_dir_abs, member_name)
                
                # Get the real, absolute path of the intended destination
                dest_path_abs = os.path.realpath(dest_path)

                # Security check: Ensure the destination path is within the destination directory
                if not dest_path_abs.startswith(dest_dir_abs + os.sep) and dest_path_abs != dest_dir_abs:
                    print(f"Path traversal attempt detected for entry: {member_name}. Skipping.")
                    continue

                if member_info.is_dir():
                    os.makedirs(dest_path_abs, exist_ok=True)
                else:
                    # Ensure parent directory exists
                    parent_dir = os.path.dirname(dest_path_abs)
                    if not os.path.exists(parent_dir):
                        os.makedirs(parent_dir, exist_ok=True)
                    
                    # Extract file content manually to be safe
                    with zf.open(member_info) as source, open(dest_path_abs, "wb") as target:
                        shutil.copyfileobj(source, target)
        return True
    except (zipfile.BadZipFile, IOError, OSError) as e:
        print(f"Error during ZIP extraction: {e}")
        return False

def create_test_zip(zip_file_path: str):
    """Creates a test zip file for extraction tests."""
    with zipfile.ZipFile(zip_file_path, 'w') as zf:
        # 1. Normal file
        zf.writestr("test1.txt", "This is a test file.")
        # 2. File in a subdirectory
        zf.writestr("dir1/test2.txt", "This is a nested file.")
        # 3. Path traversal attempt
        zf.writestr("../evil.txt", "This should not be extracted.")
        # 4. Absolute path attempt (zipfile usually sanitizes this, but we test defensively)
        zf.writestr("/tmp/absolute.txt", "This should also not be extracted.")
        # 5. Another safe file
        zf.writestr("test3.txt", "This is another safe file.")


def main():
    """Main function to run test cases."""
    zip_file_name = "archive.zip"
    unpack_dir = "/tmp/unpack_python"
    
    # --- Test Case 1: Standard Extraction ---
    print("--- Test Case 1: Standard Extraction ---")
    try:
        create_test_zip(zip_file_name)
        print(f"Created test zip: {zip_file_name}")

        success = extract_archive(zip_file_name, unpack_dir)
        print(f"Extraction successful: {success}")

        # Verify results
        print(f"Exists '{unpack_dir}/test1.txt': {os.path.exists(os.path.join(unpack_dir, 'test1.txt'))}")
        print(f"Exists '{unpack_dir}/dir1/test2.txt': {os.path.exists(os.path.join(unpack_dir, 'dir1', 'test2.txt'))}")
        print(f"Exists '{unpack_dir}/test3.txt': {os.path.exists(os.path.join(unpack_dir, 'test3.txt'))}")
        # Note: evil.txt might be created in /tmp, not relative to unpack_dir
        print(f"Exists '/tmp/evil.txt': {os.path.exists('/tmp/evil.txt')}") 
        print(f"Exists '/tmp/absolute.txt': {os.path.exists('/tmp/absolute.txt')}")

    finally:
        # Cleanup
        if os.path.isdir(unpack_dir):
            shutil.rmtree(unpack_dir)
        if os.path.exists(zip_file_name):
            os.remove(zip_file_name)
        if os.path.exists('/tmp/evil.txt'):
            os.remove('/tmp/evil.txt')
        if os.path.exists('/tmp/absolute.txt'):
            os.remove('/tmp/absolute.txt')
        print("Cleaned up test files and directories.\n")

    # --- Test Case 2: Non-existent ZIP file ---
    print("--- Test Case 2: Non-existent ZIP file ---")
    success2 = extract_archive("nonexistent.zip", unpack_dir)
    print(f"Extraction successful: {success2}\n")

    # --- Test Case 3: Destination is a file (should fail) ---
    print("--- Test Case 3: Destination is a file ---")
    dummy_file = "dummy_file.txt"
    try:
        with open(dummy_file, "w") as f:
            f.write("dummy")
        create_test_zip(zip_file_name)
        success3 = extract_archive(zip_file_name, dummy_file)
        print(f"Extraction successful: {success3}")
    finally:
        if os.path.exists(dummy_file):
            os.remove(dummy_file)
        if os.path.exists(zip_file_name):
            os.remove(zip_file_name)
        print("Cleaned up.\n")
        
    # Test cases 4 and 5 are implicitly handled by the malicious zip created in Test 1.
    print("--- Test Cases 4 & 5: Path Traversal and Absolute Paths are handled in Test 1 ---")

if __name__ == "__main__":
    main()