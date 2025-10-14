import os
import zipfile
import tarfile
import shutil
import pathlib

def extract_archive(archive_path: str, dest_dir: str):
    """
    Extracts a ZIP or TAR archive to a destination directory with security checks.
    
    Args:
        archive_path (str): The path to the archive file.
        dest_dir (str): The directory where contents will be extracted.
        
    Raises:
        ValueError: If the archive format is not supported.
        IOError: If a path traversal attempt is detected.
        FileNotFoundError: If the archive_path does not exist.
    """
    if not os.path.exists(archive_path):
        raise FileNotFoundError(f"Archive not found at: {archive_path}")

    # Use pathlib for robust path operations
    dest_path_obj = pathlib.Path(dest_dir).resolve()
    dest_path_obj.mkdir(parents=True, exist_ok=True)
    
    archive_path_lower = archive_path.lower()
    
    if archive_path_lower.endswith(('.zip')):
        _extract_zip(archive_path, dest_path_obj)
    elif archive_path_lower.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2')):
        _extract_tar(archive_path, dest_path_obj)
    else:
        raise ValueError(f"Unsupported archive format for: {archive_path}")

def _extract_zip(archive_path: str, dest_path_obj: pathlib.Path):
    """Helper to extract ZIP files securely."""
    with zipfile.ZipFile(archive_path, 'r') as zf:
        for member in zf.infolist():
            target_path = (dest_path_obj / member.filename).resolve()
            
            # Security Check: Path Traversal (Zip Slip)
            if dest_path_obj not in target_path.parents and target_path != dest_path_obj:
                 raise IOError(f"Zip Slip vulnerability detected in member: {member.filename}")
            
            zf.extract(member, dest_path_obj)

def _extract_tar(archive_path: str, dest_path_obj: pathlib.Path):
    """Helper to extract TAR files securely."""
    # 'r:*' automatically handles compression like gz, bz2
    with tarfile.open(archive_path, 'r:*') as tf:
        for member in tf.getmembers():
            target_path = (dest_path_obj / member.name).resolve()

            # Security Check: Path Traversal
            if dest_path_obj not in target_path.parents and target_path != dest_path_obj:
                 raise IOError(f"Path traversal vulnerability detected in member: {member.name}")

            tf.extract(member, dest_path_obj, filter='data')


def main():
    """Main function with test cases."""
    test_dir = "python_test_area"
    
    try:
        # Setup
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
        os.makedirs(test_dir)

        zip_path = os.path.join(test_dir, "test.zip")
        tar_path = os.path.join(test_dir, "test.tar.gz")

        # Create a test zip file
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("file1.txt", "This is file 1.")
            zf.writestr("subdir/file2.txt", "This is file 2.")
            zf.writestr("../malicious.txt", "This should not be extracted.")

        # Create a test tar file
        with tarfile.open(tar_path, 'w:gz') as tf:
            # Tarfile is more strict and often disallows '..' by default,
            # but we still check for it.
            # We add a valid file for extraction test.
            with open(os.path.join(test_dir, 'temp.txt'), 'w') as f:
                f.write('This is a tar file.')
            tf.add(os.path.join(test_dir, 'temp.txt'), arcname='tar_file.txt')

        # --- Test Cases ---
        
        # Test Case 1: Successful ZIP extraction
        print("--- Test Case 1: Standard ZIP Extraction ---")
        dest1 = os.path.join(test_dir, "output1")
        try:
            extract_archive(zip_path, dest1)
            print(f"Successfully extracted to {dest1}")
            if os.path.exists(os.path.join(dest1, "file1.txt")):
                print("Verification: PASSED")
            else:
                print("Verification: FAILED")
        except Exception as e:
            print(f"Extraction failed: {e}")
        
        # Test Case 2: Successful TAR extraction
        print("\n--- Test Case 2: Standard TAR Extraction ---")
        dest2 = os.path.join(test_dir, "output2")
        try:
            extract_archive(tar_path, dest2)
            print(f"Successfully extracted to {dest2}")
            if os.path.exists(os.path.join(dest2, "tar_file.txt")):
                print("Verification: PASSED")
            else:
                print("Verification: FAILED")
        except Exception as e:
            print(f"Extraction failed: {e}")

        # Test Case 3: Path Traversal security test
        print("\n--- Test Case 3: Path Traversal (Zip Slip) Test ---")
        dest3 = os.path.join(test_dir, "output3")
        try:
            extract_archive(zip_path, dest3)
            print("Extraction completed without error (this may be a fail).")
            if os.path.exists(os.path.join(test_dir, "malicious.txt")):
                print("Verification: FAILED - Malicious file was created.")
            else:
                print("Verification: PASSED - Malicious file was blocked.")
        except Exception as e:
            print(f"Caught expected security exception: {e}")

        # Test Case 4: Non-existent archive file
        print("\n--- Test Case 4: Non-existent Archive File ---")
        dest4 = os.path.join(test_dir, "output4")
        try:
            extract_archive("non_existent.zip", dest4)
        except Exception as e:
            print(f"Caught expected exception: {e}")

        # Test Case 5: Unsupported archive type
        print("\n--- Test Case 5: Unsupported Archive Type ---")
        dummy_rar = os.path.join(test_dir, "test.rar")
        with open(dummy_rar, "w") as f:
            f.write("dummy")
        dest5 = os.path.join(test_dir, "output5")
        try:
            extract_archive(dummy_rar, dest5)
        except Exception as e:
            print(f"Caught expected exception: {e}")

    finally:
        # Cleanup
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
            print("\nCleaned up test directory.")


if __name__ == "__main__":
    main()