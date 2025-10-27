import tarfile
import os
import shutil
import pathlib

def extract_tar(tar_file_path: str, dest_dir_path: str):
    """
    Extracts a TAR archive to a specified directory, preventing path traversal.
    
    Args:
        tar_file_path (str): The path to the .tar file.
        dest_dir_path (str): The path to the destination directory.
    
    Raises:
        ValueError: If a path traversal attack is detected.
    """
    # Resolve the destination directory to an absolute path for security checks
    dest_dir_abs = os.path.abspath(dest_dir_path)
    os.makedirs(dest_dir_abs, exist_ok=True)

    with tarfile.open(tar_file_path, "r") as tar:
        # It's crucial to iterate and check each member instead of using extractall() directly,
        # which can be vulnerable to path traversal attacks (Zip Slip).
        for member in tar.getmembers():
            # Construct the full destination path for the member
            member_dest_path = os.path.join(dest_dir_abs, member.name)
            
            # Security Check: Resolve the member's destination path to an absolute path
            member_dest_abs = os.path.abspath(member_dest_path)
            
            # Ensure the extracted file will be inside the destination directory
            if not member_dest_abs.startswith(dest_dir_abs):
                raise ValueError(f"Path traversal attempt detected: '{member.name}'")
            
            # The member is safe, extract it
            tar.extract(member, path=dest_dir_abs)
            
def create_tar_file(tar_file_path: str, files_to_add: dict):
    """
    Creates a TAR file.
    
    Args:
        tar_file_path (str): The path of the TAR file to create.
        files_to_add (dict): A dictionary mapping file paths to their names in the archive.
    """
    with tarfile.open(tar_file_path, "w") as tar:
        for file_path, arcname in files_to_add.items():
            tar.add(file_path, arcname=arcname)

def main():
    """Main function with test cases."""
    # --- Test Case Setup ---
    pathlib.Path("test_data/subdir").mkdir(parents=True, exist_ok=True)
    with open("test_data/file1.txt", "w") as f:
        f.write("hello")
    with open("test_data/subdir/file2.txt", "w") as f:
        f.write("world")

    # --- Test Cases ---
    test_cases = [
        {"name": "test_case_1_normal", "files": {"test_data/file1.txt": "file1.txt", "test_data/subdir/file2.txt": "subdir/file2.txt"}},
        {"name": "test_case_2_empty_tar", "files": {}},
        {"name": "test_case_3_nested_dirs", "files": {"test_data/file1.txt": "a/b/c/file1.txt"}},
        {"name": "test_case_4_malicious_path_abs", "files": {"test_data/file1.txt": "/tmp/evil.txt"}},
        {"name": "test_case_5_malicious_path_rel", "files": {"test_data/file1.txt": "../../evil.txt"}}
    ]

    for test in test_cases:
        test_name = test["name"]
        tar_file = f"{test_name}.tar"
        unpack_dir = f"/tmp/unpack_python_{test_name}"
        
        print(f"--- Running {test_name} ---")
        try:
            # 1. Create the TAR file for the test case
            create_tar_file(tar_file, test["files"])

            # 2. Run the extraction
            print(f"Extracting {tar_file} to {unpack_dir}")
            extract_tar(tar_file, unpack_dir)
            print("Extraction successful.")
            
        except (ValueError, tarfile.ReadError) as e:
            print(f"Caught expected exception for malicious input or I/O error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        finally:
            # 3. Cleanup
            if os.path.exists(tar_file):
                os.remove(tar_file)
            if os.path.exists(unpack_dir):
                shutil.rmtree(unpack_dir)
            print(f"Cleaned up {tar_file} and {unpack_dir}")
            print()

    # --- Global Test Cleanup ---
    if os.path.exists("test_data"):
        shutil.rmtree("test_data")

if __name__ == "__main__":
    main()