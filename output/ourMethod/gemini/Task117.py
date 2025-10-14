import zipfile
import os
import pathlib
import shutil

def extract_zip(zip_file_path: str, dest_dir: str) -> bool:
    """
    Extracts a zip file to a destination directory, preventing path traversal.

    :param zip_file_path: Path to the .zip file.
    :param dest_dir: Directory to extract files to.
    :return: True if successful, False otherwise.
    """
    try:
        dest_path = pathlib.Path(dest_dir).resolve()
        dest_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error creating destination directory: {e}")
        return False

    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zf:
            for member in zf.infolist():
                # Resolve the full path for the member
                member_path = (dest_path / member.filename).resolve()

                # Security Check: Ensure the resolved path is within the destination directory
                if not str(member_path).startswith(str(dest_path)):
                    print(f"Path traversal attempt detected. Skipping: {member.filename}")
                    continue

                if member.is_dir():
                    member_path.mkdir(parents=True, exist_ok=True)
                else:
                    # Ensure parent directory exists
                    member_path.parent.mkdir(parents=True, exist_ok=True)
                    # Extract file
                    with zf.open(member) as source, open(member_path, "wb") as target:
                        shutil.copyfileobj(source, target)
        return True
    except zipfile.BadZipFile:
        print(f"Error: Invalid zip file '{zip_file_path}'")
        return False
    except FileNotFoundError:
        print(f"Error: Archive file not found at '{zip_file_path}'")
        return False
    except Exception as e:
        print(f"An error occurred during extraction: {e}")
        return False

# --- Test Cases ---

def create_test_zip(zip_filename: str, include_traversal: bool):
    """Creates a zip file for testing purposes."""
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('file1.txt', 'This is file 1.')
        zf.writestr('dir1/file2.txt', 'This is file 2.')
        
        # Add an empty directory
        dir_info = zipfile.ZipInfo('dir1/emptydir/')
        dir_info.external_attr = 0o40755 << 16  # drwxr-xr-x
        zf.writestr(dir_info, '')

        if include_traversal:
            # Add a malicious path entry
            zf.writestr('../../evil.txt', 'malicious content')

def run_tests():
    """Sets up a test environment and runs all test cases."""
    print("--- Running Python ZIP Extraction Tests ---")
    temp_dir = pathlib.Path("python_test_temp")
    
    try:
        # Setup
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        temp_dir.mkdir()

        test_zip = temp_dir / "test.zip"
        traversal_zip = temp_dir / "traversal.zip"
        create_test_zip(str(test_zip), include_traversal=False)
        create_test_zip(str(traversal_zip), include_traversal=True)

        # Test Case 1: Normal extraction
        print("\n[Test 1] Normal Extraction")
        out1 = temp_dir / "out1"
        success1 = extract_zip(str(test_zip), str(out1))
        result1 = success1 and (out1 / "dir1" / "file2.txt").exists()
        print(f"Result: {'PASS' if result1 else 'FAIL'}")

        # Test Case 2: Extraction to a non-existent directory
        print("\n[Test 2] Extract to New Directory")
        out2 = temp_dir / "out2_new"
        success2 = extract_zip(str(test_zip), str(out2))
        result2 = success2 and (out2 / "file1.txt").exists()
        print(f"Result: {'PASS' if result2 else 'FAIL'}")

        # Test Case 3: Path traversal attack
        print("\n[Test 3] Path Traversal Attack")
        out3 = temp_dir / "out3"
        extract_zip(str(traversal_zip), str(out3))
        evil_file = temp_dir.parent / "evil.txt" # The attack tries to create a file here
        result3 = not evil_file.exists()
        print(f"Result: {'PASS' if result3 else 'FAIL'}")

        # Test Case 4: Non-existent archive file
        print("\n[Test 4] Non-existent Archive")
        out4 = temp_dir / "out4"
        success4 = extract_zip("nonexistent.zip", str(out4))
        print(f"Result: {'PASS' if not success4 else 'FAIL'}")

        # Test Case 5: Output is a file
        print("\n[Test 5] Output is a File")
        out_file = temp_dir / "output_file.txt"
        out_file.touch()
        success5 = extract_zip(str(test_zip), str(out_file))
        print(f"Result: {'PASS' if not success5 else 'FAIL'}")

    finally:
        # Cleanup
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        if pathlib.Path("evil.txt").exists():
            pathlib.Path("evil.txt").unlink()

if __name__ == "__main__":
    run_tests()