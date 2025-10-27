import zipfile
import os
import shutil
import tempfile
from pathlib import Path

def extract_zip_secure(zip_path: str, dest_dir: str):
    """
    Securely extracts a zip file to a specified directory, preventing path traversal.
    The prompt mentions "open... as a tarfile", which is technically incorrect for a .zip file.
    This function interprets the request as extracting a standard ZIP archive.
    
    Args:
        zip_path (str): The path to the zip file.
        dest_dir (str): The directory to extract files into.

    Returns:
        bool: True if successful, False otherwise.
    """
    if not os.path.exists(zip_path):
        print(f"Error: Zip file not found at '{zip_path}'")
        return False

    dest_path_obj = Path(dest_dir).resolve()
    
    # Create destination and ensure it's a directory
    try:
        os.makedirs(dest_path_obj, exist_ok=True)
    except OSError as e:
        print(f"Error: Could not create destination directory '{dest_path_obj}': {e}")
        return False
    
    if not os.path.isdir(dest_path_obj):
        print(f"Error: Destination '{dest_path_obj}' exists but is not a directory.")
        return False

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Construct the full path for the member
                target_path = dest_path_obj / member.filename
                
                # Resolve the real path to prevent traversal attacks
                resolved_target_path = target_path.resolve()

                # Security Check: Ensure the resolved path is within the destination directory
                if dest_path_obj not in resolved_target_path.parents and resolved_target_path != dest_path_obj:
                    print(f"Security Error: Skipping '{member.filename}' as it extracts outside the target directory.")
                    continue
                
                if member.is_dir():
                    os.makedirs(resolved_target_path, exist_ok=True)
                else:
                    # Ensure parent directory of the file exists
                    os.makedirs(resolved_target_path.parent, exist_ok=True)
                    # Extract the file
                    with zip_ref.open(member, 'r') as source, open(resolved_target_path, 'wb') as target:
                        shutil.copyfileobj(source, target)
    except (zipfile.BadZipFile, IOError) as e:
        print(f"Error extracting zip file: {e}")
        return False
        
    return True

def create_test_zip(zip_path: str, file_entries: list):
    """Helper function to create a zip file for testing."""
    with zipfile.ZipFile(zip_path, 'w') as zf:
        for entry_name in file_entries:
            # For directories, ZipInfo is needed. For files, write content.
            if entry_name.endswith('/'):
                 zf.writestr(zipfile.ZipInfo(entry_name), b'')
            else:
                zf.writestr(entry_name, f"content of {entry_name}".encode('utf-8'))

def main():
    """Main function with test cases."""
    test_root = Path(tempfile.gettempdir()) / "lse50_python_test"

    # Clean up previous runs
    if test_root.exists():
        shutil.rmtree(test_root)
    test_root.mkdir(parents=True)

    try:
        # Test Case 1: Normal, safe extraction
        print("--- Test Case 1: Normal Extraction ---")
        safe_zip = test_root / "archive_safe.zip"
        safe_dest = test_root / "unpack_safe"
        create_test_zip(str(safe_zip), ["file1.txt", "dir1/", "dir1/file2.txt"])
        success1 = extract_zip_secure(str(safe_zip), str(safe_dest))
        print(f"Extraction successful: {success1}")
        final_file = safe_dest / "dir1" / "file2.txt"
        print(f"Exists '{final_file}': {final_file.exists()}")
        print()

        # Test Case 2: Path Traversal attack
        print("--- Test Case 2: Path Traversal Attack ---")
        evil_zip = test_root / "archive_evil.zip"
        evil_dest = test_root / "unpack_evil"
        create_test_zip(str(evil_zip), ["../../evil.txt"])
        success2 = extract_zip_secure(str(evil_zip), str(evil_dest))
        print(f"Extraction reported success (should handle gracefully): {success2}")
        malicious_file = test_root.parent / "evil.txt"
        print(f"Malicious file created at '{malicious_file}': {malicious_file.exists()}")
        print()
        
        # Test Case 3: Absolute Path attack
        print("--- Test Case 3: Absolute Path Attack ---")
        abs_zip = test_root / "archive_abs.zip"
        abs_dest = test_root / "unpack_abs"
        # Note: zipfile module typically sanitizes this on its own, but our check adds a layer.
        abs_path_entry = str(test_root / "absolute.txt")
        # For cross-platform, remove drive letter on Windows for zip entry
        if os.name == 'nt':
            abs_path_entry = abs_path_entry[2:] # Remove C:
        create_test_zip(str(abs_zip), [abs_path_entry])
        success3 = extract_zip_secure(str(abs_zip), str(abs_dest))
        print(f"Extraction reported success (should handle gracefully): {success3}")
        print(f"Malicious absolute file created at '{abs_path_entry}': {Path(abs_path_entry).is_absolute() and Path(abs_path_entry).exists()}")
        print()

        # Test Case 4: Zip file not found
        print("--- Test Case 4: Zip File Not Found ---")
        non_existent_zip = test_root / "nonexistent.zip"
        dest4 = test_root / "unpack_4"
        success4 = extract_zip_secure(str(non_existent_zip), str(dest4))
        print(f"Extraction successful: {success4}")
        print()

        # Test Case 5: Destination is a file, not a directory
        print("--- Test Case 5: Destination is a File ---")
        dest5_file = test_root / "destination_is_file.txt"
        dest5_file.touch()
        success5 = extract_zip_secure(str(safe_zip), str(dest5_file))
        print(f"Extraction successful: {success5}")
        print()

    finally:
        # Cleanup
        print("--- Cleaning up test files ---")
        shutil.rmtree(test_root)
        print("Cleanup complete.")

if __name__ == "__main__":
    main()