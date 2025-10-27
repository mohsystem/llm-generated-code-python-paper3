import os
import zipfile
import shutil

def unzip_archive(zip_path, extract_to_dir):
    """
    Unzips all files from a zip archive to a specified directory.
    Note: The prompt mentions 'tarfile' but the filename is 'archive.zip'.
          This function handles a .zip file as implied by the name.
    """
    try:
        # Create the target directory if it doesn't exist
        os.makedirs(extract_to_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to_dir)
        return True
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        print(f"Error: {e}")
        return False

# --- Test Case Helper Functions ---

def create_test_zip(zip_path, test_num):
    """Creates a dummy zip file for testing."""
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        # A file in the root
        file_content = f"This is content for test case {test_num}".encode('utf-8')
        zipf.writestr(f'test_file_{test_num}.txt', file_content)
        # A file in a subdirectory
        zipf.writestr(f'subdir/test_file_{test_num}.txt', file_content)

def main():
    """Main function to run test cases."""
    zip_file_path = "archive.zip"
    extract_dir = "/tmp/unpack"

    for i in range(1, 6):
        print(f"--- Running Test Case {i} ---")
        success = True
        
        try:
            # 1. Setup: Clean up previous run and create new test zip
            if os.path.exists(zip_file_path):
                os.remove(zip_file_path)
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
            
            create_test_zip(zip_file_path, i)
            print(f"Created {zip_file_path} for test {i}")
            
            # 2. Execute
            if not unzip_archive(zip_file_path, extract_dir):
                raise Exception("Unzip function returned False.")
            print(f"Unzipped {zip_file_path} to {extract_dir}")
            
            # 3. Verify
            expected_file1 = os.path.join(extract_dir, f'test_file_{i}.txt')
            expected_file2 = os.path.join(extract_dir, 'subdir', f'test_file_{i}.txt')
            
            if not os.path.exists(expected_file1) or not os.path.exists(expected_file2):
                print("Verification failed: Extracted files not found.")
                success = False
            else:
                with open(expected_file1, 'r') as f:
                    content = f.read()
                    if content != f"This is content for test case {i}":
                        print("Verification failed: File content mismatch.")
                        success = False

        except Exception as e:
            print(f"An error occurred: {e}")
            success = False
        finally:
            # 4. Cleanup
            if os.path.exists(zip_file_path):
                os.remove(zip_file_path)
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
            
            print(f"Test Case {i}: {'PASS' if success else 'FAIL'}")

if __name__ == '__main__':
    main()