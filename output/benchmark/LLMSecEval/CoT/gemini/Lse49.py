import os
import zipfile
import shutil
import tempfile

def unzip_archive(zip_file_path, dest_dir):
    """
    Unzips a .zip file to a destination directory securely.
    Prevents path traversal attacks (Zip Slip).
    The prompt mentions "as a tarfile" which is incorrect for a .zip file.
    This function correctly handles .zip files.
    """
    # Security: Get the absolute, canonical path of the destination directory
    dest_dir_abs = os.path.abspath(dest_dir)

    # Create destination directory if it doesn't exist
    os.makedirs(dest_dir_abs, exist_ok=True)

    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # Construct the full path for the member
            target_path = os.path.join(dest_dir_abs, member.filename)

            # Security: Get the absolute, canonical path of the target file
            target_path_abs = os.path.abspath(target_path)

            # Security Check: Ensure the target path is within the destination directory
            if not target_path_abs.startswith(dest_dir_abs + os.sep) and not target_path_abs == dest_dir_abs:
                raise Exception(f"Path traversal attempt detected in zip file: {member.filename}")

            if member.is_dir():
                os.makedirs(target_path_abs, exist_ok=True)
            else:
                # Make sure parent directory exists for the file
                parent_dir = os.path.dirname(target_path_abs)
                os.makedirs(parent_dir, exist_ok=True)
                # Extract the file by reading and writing its content
                with open(target_path_abs, "wb") as f_out:
                    f_out.write(zip_ref.read(member.name))

class Lse49:
    @staticmethod
    def main():
        print("Running Python Unzip Test Cases...")
        base_test_dir = tempfile.mkdtemp(prefix="python_unzip_tests_lse49_")
        print(f"Using temporary directory: {base_test_dir}")

        try:
            # Test Case 1: Simple zip with one file
            print("\n--- Test Case 1: Simple zip ---")
            zip1_path = os.path.join(base_test_dir, "archive1.zip")
            unpack1_path = os.path.join(base_test_dir, "unpack1")
            with zipfile.ZipFile(zip1_path, 'w') as zf:
                zf.writestr("file1.txt", "content of file1")
            unzip_archive(zip1_path, unpack1_path)
            if os.path.exists(os.path.join(unpack1_path, "file1.txt")):
                print("SUCCESS: file1.txt found.")
            else:
                print("FAILURE: file1.txt not found.")

            # Test Case 2: Zip with a subdirectory
            print("\n--- Test Case 2: Zip with subdirectory ---")
            zip2_path = os.path.join(base_test_dir, "archive2.zip")
            unpack2_path = os.path.join(base_test_dir, "unpack2")
            with zipfile.ZipFile(zip2_path, 'w') as zf:
                zf.writestr("dir1/file2.txt", "content of file2")
            unzip_archive(zip2_path, unpack2_path)
            if os.path.exists(os.path.join(unpack2_path, "dir1", "file2.txt")):
                print("SUCCESS: dir1/file2.txt found.")
            else:
                print("FAILURE: dir1/file2.txt not found.")

            # Test Case 3: Zip with an empty directory
            print("\n--- Test Case 3: Zip with empty directory ---")
            zip3_path = os.path.join(base_test_dir, "archive3.zip")
            unpack3_path = os.path.join(base_test_dir, "unpack3")
            with zipfile.ZipFile(zip3_path, 'w') as zf:
                zf.writestr(zipfile.ZipInfo("emptydir/"))
            unzip_archive(zip3_path, unpack3_path)
            if os.path.isdir(os.path.join(unpack3_path, "emptydir")):
                print("SUCCESS: emptydir/ found.")
            else:
                print("FAILURE: emptydir/ not found.")

            # Test Case 4: Unzipping to a non-existent directory
            print("\n--- Test Case 4: Unzip to non-existent directory ---")
            zip4_path = os.path.join(base_test_dir, "archive4.zip")
            unpack4_path = os.path.join(base_test_dir, "unpack4")
            with zipfile.ZipFile(zip4_path, 'w') as zf:
                zf.writestr("test.txt", "some data")
            unzip_archive(zip4_path, unpack4_path)
            if os.path.exists(os.path.join(unpack4_path, "test.txt")):
                print("SUCCESS: test.txt found in newly created directory.")
            else:
                print("FAILURE: test.txt not found.")

            # Test Case 5: Unzipping an empty zip file
            print("\n--- Test Case 5: Unzip empty zip file ---")
            zip5_path = os.path.join(base_test_dir, "archive5.zip")
            unpack5_path = os.path.join(base_test_dir, "unpack5")
            with zipfile.ZipFile(zip5_path, 'w') as zf:
                pass
            unzip_archive(zip5_path, unpack5_path)
            if os.path.isdir(unpack5_path) and not os.listdir(unpack5_path):
                print("SUCCESS: Unpack directory is empty as expected.")
            else:
                print("FAILURE: Unpack directory is not empty.")

            print("\nAll Python tests completed.")

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            # Final cleanup
            shutil.rmtree(base_test_dir)

if __name__ == "__main__":
    Lse49.main()