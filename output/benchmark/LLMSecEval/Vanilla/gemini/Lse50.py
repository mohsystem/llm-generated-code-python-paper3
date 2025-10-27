import os
import zipfile
import shutil
from pathlib import Path

def extract_zip(zip_path: str, extract_to_dir: str):
    """
    Extracts all files from a zip archive to a specified directory.
    Creates the destination directory if it does not exist.

    :param zip_path: Path to the .zip file.
    :param extract_to_dir: Path to the destination directory.
    :return: True if extraction is successful, False otherwise.
    """
    if not os.path.exists(zip_path):
        print(f"Error: ZIP file not found at '{zip_path}'")
        return False

    try:
        # Create the destination directory if it doesn't exist
        os.makedirs(extract_to_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to_dir)
        # print(f"Successfully extracted '{zip_path}' to '{extract_to_dir}'")
        return True
    except zipfile.BadZipFile:
        print(f"Error: The file '{zip_path}' is not a valid zip file.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def create_test_zip(zip_name, files_to_add):
    """Helper to create a zip file for testing."""
    with zipfile.ZipFile(zip_name, 'w') as zf:
        for path, content in files_to_add.items():
            path_obj = Path(path)
            if content is None: # It's a directory
                # zipfile automatically creates directories based on file paths
                # To create an empty dir, we add a ZipInfo object
                dir_info = zipfile.ZipInfo(f"{path_obj.as_posix()}/")
                zf.writestr(dir_info, "")
            else:
                zf.writestr(path, content)

if __name__ == "__main__":
    print("Running Python Lse50 tests...")
    dest_dir = "/tmp/unpack"

    # Test Case 1 & 2: Basic extraction and creating destination directory
    print("\n--- Test Case 1 & 2: Basic Extraction ---")
    zip_file = "archive1.zip"
    dest_path = Path(dest_dir)
    if dest_path.exists():
        shutil.rmtree(dest_path)
    
    create_test_zip(zip_file, {"file1.txt": "hello", "dir1/file2.txt": "world"})
    
    if extract_zip(zip_file, dest_dir):
        file1 = dest_path / "file1.txt"
        file2 = dest_path / "dir1/file2.txt"
        if file1.exists() and file1.read_text() == "hello" and file2.exists() and file2.read_text() == "world":
            print("PASS: Files extracted successfully.")
        else:
            print("FAIL: File extraction verification failed.")
    else:
        print("FAIL: Extraction function returned False.")
    # Cleanup
    Path(zip_file).unlink()
    if dest_path.exists():
        shutil.rmtree(dest_path)

    # Test Case 3: Non-existent zip file
    print("\n--- Test Case 3: Non-existent ZIP file ---")
    if not extract_zip("nonexistent.zip", dest_dir):
        print("PASS: Correctly handled non-existent zip file.")
    else:
        print("FAIL: Should have returned False for non-existent file.")

    # Test Case 4: Extracting an empty zip file
    print("\n--- Test Case 4: Empty ZIP file ---")
    zip_file = "archive_empty.zip"
    dest_path = Path(dest_dir)
    if dest_path.exists():
        shutil.rmtree(dest_path)
    
    create_test_zip(zip_file, {})
    
    if extract_zip(zip_file, dest_dir):
        if dest_path.exists() and not any(dest_path.iterdir()):
            print("PASS: Empty zip extracted correctly (empty directory created).")
        else:
            print("FAIL: Directory should be empty after extraction.")
    else:
        print("FAIL: Extraction function returned False.")
    # Cleanup
    Path(zip_file).unlink()
    if dest_path.exists():
        shutil.rmtree(dest_path)

    # Test Case 5: Overwriting existing files
    print("\n--- Test Case 5: Overwriting existing files ---")
    zip_file = "archive_overwrite.zip"
    dest_path = Path(dest_dir)
    if dest_path.exists():
        shutil.rmtree(dest_path)
    dest_path.mkdir(parents=True)
    existing_file = dest_path / "file.txt"
    existing_file.write_text("old content")
    
    create_test_zip(zip_file, {"file.txt": "new content"})
    
    if extract_zip(zip_file, dest_dir):
        if existing_file.read_text() == "new content":
            print("PASS: File was successfully overwritten.")
        else:
            print("FAIL: File content was not overwritten.")
    else:
        print("FAIL: Extraction function returned False.")
    # Cleanup
    Path(zip_file).unlink()
    if dest_path.exists():
        shutil.rmtree(dest_path)