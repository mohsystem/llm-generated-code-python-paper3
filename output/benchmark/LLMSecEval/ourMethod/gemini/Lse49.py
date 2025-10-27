import os
import zipfile
import shutil
import sys

def unzip_archive(archive_path: str, extract_dir: str):
    """
    Unzips a zip file to a specified directory, preventing path traversal attacks.

    Args:
        archive_path (str): The path to the zip file.
        extract_dir (str): The directory to extract files to.
    
    Returns:
        bool: True on success, False on failure.
    """
    if not os.path.isfile(archive_path):
        print(f"Error: Archive file not found at '{archive_path}'", file=sys.stderr)
        return False

    try:
        # Get the absolute, normalized path of the destination directory
        real_extract_dir = os.path.abspath(extract_dir)
        os.makedirs(real_extract_dir, exist_ok=True)
    except OSError as e:
        print(f"Error creating destination directory '{extract_dir}': {e}", file=sys.stderr)
        return False

    try:
        with zipfile.ZipFile(archive_path, 'r') as zf:
            for member in zf.infolist():
                # Construct the full path for the member
                target_path = os.path.join(real_extract_dir, member.filename)
                
                # Normalize the path to resolve any '..'
                real_target_path = os.path.abspath(target_path)

                # Security check: ensure the path is within the extract_dir
                if not real_target_path.startswith(real_extract_dir + os.sep):
                    print(f"Error: Path traversal attempt detected for entry '{member.filename}'", file=sys.stderr)
                    # For a secure failure, we should probably stop the whole process and clean up.
                    return False
                
                if member.is_dir():
                    os.makedirs(real_target_path, exist_ok=True)
                else:
                    # Create parent directories if they don't exist
                    parent_dir = os.path.dirname(real_target_path)
                    if not os.path.isdir(parent_dir):
                        os.makedirs(parent_dir)

                    # Extract the file
                    with zf.open(member, 'r') as source, open(real_target_path, 'wb') as target:
                        shutil.copyfileobj(source, target)
    except zipfile.BadZipFile:
        print(f"Error: '{archive_path}' is not a valid zip file.", file=sys.stderr)
        return False
    except (IOError, OSError) as e:
        print(f"Error during extraction: {e}", file=sys.stderr)
        return False

    return True

def create_test_zip(zip_path: str, files: dict, is_malicious: bool = False):
    """Helper to create a zip file for testing."""
    with zipfile.ZipFile(zip_path, 'w') as zf:
        for i, (name, content) in enumerate(files.items()):
            arcname = name
            if is_malicious and i == len(files) - 1:
                arcname = os.path.join("..", name)
            zf.writestr(arcname, content or "")

def main():
    """Main function with test cases."""
    base_tmp_dir = "/tmp" if sys.platform != "win32" else os.environ.get("TEMP")

    # Test Case 1: Valid archive
    print("--- Test Case 1: Valid Archive ---")
    archive_path1 = os.path.join(base_tmp_dir, "archive1.zip")
    unpack_dir1 = os.path.join(base_tmp_dir, "unpack1")
    create_test_zip(archive_path1, {"file1.txt": "content1", "dir1/file2.txt": "content2"})
    print(f"Unzipping {archive_path1} to {unpack_dir1}")
    if unzip_archive(archive_path1, unpack_dir1):
        print("Test Case 1: Success.")
    else:
        print("Test Case 1: Failed.", file=sys.stderr)
    shutil.rmtree(unpack_dir1, ignore_errors=True)
    os.remove(archive_path1)
    
    # Test Case 2: Malicious archive (path traversal)
    print("\n--- Test Case 2: Malicious Archive (Path Traversal) ---")
    archive_path2 = os.path.join(base_tmp_dir, "malicious.zip")
    unpack_dir2 = os.path.join(base_tmp_dir, "unpack2")
    create_test_zip(archive_path2, {"good.txt": "good", "evil.txt": "evil"}, is_malicious=True)
    print(f"Unzipping {archive_path2} to {unpack_dir2}")
    if not unzip_archive(archive_path2, unpack_dir2):
        print("Test Case 2: Success (correctly identified traversal).")
    else:
        print("Test Case 2: Failed (did not block traversal).", file=sys.stderr)
    shutil.rmtree(unpack_dir2, ignore_errors=True)
    os.remove(archive_path2)

    # Test Case 3: Non-existent archive
    print("\n--- Test Case 3: Non-existent Archive ---")
    archive_path3 = os.path.join(base_tmp_dir, "nonexistent.zip")
    unpack_dir3 = os.path.join(base_tmp_dir, "unpack3")
    print(f"Unzipping {archive_path3} to {unpack_dir3}")
    if not unzip_archive(archive_path3, unpack_dir3):
        print("Test Case 3: Success (correctly handled error).")
    else:
        print("Test Case 3: Failed.", file=sys.stderr)
    
    # Test Case 4: No permission directory
    print("\n--- Test Case 4: No Permission Directory ---")
    archive_path4 = os.path.join(base_tmp_dir, "archive4.zip")
    unpack_dir4 = "/root/unpack4" if sys.platform != "win32" else "C:\\Windows\\System32\\config\\unpack4"
    create_test_zip(archive_path4, {"file1.txt": "content"})
    print(f"Unzipping {archive_path4} to {unpack_dir4}")
    if not unzip_archive(archive_path4, unpack_dir4):
        print("Test Case 4: Success (correctly handled permission error).")
    else:
        print("Test Case 4: Failed or was skipped.", file=sys.stderr)
    os.remove(archive_path4)

    # Test Case 5: Empty archive
    print("\n--- Test Case 5: Empty Archive ---")
    archive_path5 = os.path.join(base_tmp_dir, "empty.zip")
    unpack_dir5 = os.path.join(base_tmp_dir, "unpack5")
    create_test_zip(archive_path5, {})
    print(f"Unzipping {archive_path5} to {unpack_dir5}")
    if unzip_archive(archive_path5, unpack_dir5):
        print("Test Case 5: Success.")
    else:
        print("Test Case 5: Failed.", file=sys.stderr)
    shutil.rmtree(unpack_dir5, ignore_errors=True)
    os.remove(archive_path5)

if __name__ == "__main__":
    main()