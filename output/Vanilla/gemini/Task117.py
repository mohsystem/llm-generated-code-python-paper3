import os
import zipfile
import tarfile
import shutil
import io

def extract_archive(archive_path, dest_dir):
    """
    Extracts a ZIP or TAR archive to a destination directory.
    """
    if not os.path.exists(archive_path):
        print(f"Error: Archive path does not exist: {archive_path}")
        return False

    try:
        os.makedirs(dest_dir, exist_ok=True)
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(dest_dir)
            print(f"Successfully extracted ZIP archive '{archive_path}'")
            return True
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                tar_ref.extractall(dest_dir)
            print(f"Successfully extracted TAR archive '{archive_path}'")
            return True
        else:
            print(f"Error: Unsupported or corrupted archive file: {archive_path}")
            return False
    except (zipfile.BadZipFile, tarfile.TarError, FileNotFoundError) as e:
        print(f"Error extracting '{archive_path}': {e}")
        return False

def create_test_zip(zip_path, files_data):
    """Helper to create a test zip file. files_data is a dict of filename: content."""
    with zipfile.ZipFile(zip_path, 'w') as zf:
        for filename, content in files_data.items():
            zf.writestr(filename, content)

def create_test_tar(tar_path, files_data):
    """Helper to create a test tar file. files_data is a dict of filename: content."""
    with tarfile.open(tar_path, 'w') as tf:
        for filename, content in files_data.items():
            content_bytes = content.encode('utf-8')
            info = tarfile.TarInfo(name=filename)
            info.size = len(content_bytes)
            tf.addfile(info, io.BytesIO(content_bytes))

def main():
    test_dir = "python_test_area"
    output_dir = os.path.join(test_dir, "output")

    # Setup test environment
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)

    # --- Test Cases ---
    
    # Test Case 1: Simple ZIP file
    print("--- Test Case 1: Simple ZIP ---")
    zip1_path = os.path.join(test_dir, "test1.zip")
    out1_path = os.path.join(output_dir, "test1")
    create_test_zip(zip1_path, {"file1.txt": "This is a ZIP file."})
    extract_archive(zip1_path, out1_path)
    print("-" * 20)

    # Test Case 2: Simple TAR file
    print("--- Test Case 2: Simple TAR ---")
    tar2_path = os.path.join(test_dir, "test2.tar")
    out2_path = os.path.join(output_dir, "test2")
    create_test_tar(tar2_path, {"file2.txt": "This is a TAR file."})
    extract_archive(tar2_path, out2_path)
    print("-" * 20)

    # Test Case 3: ZIP with subdirectory
    print("--- Test Case 3: ZIP with subdirectory ---")
    zip3_path = os.path.join(test_dir, "test3.zip")
    out3_path = os.path.join(output_dir, "test3")
    create_test_zip(zip3_path, {"docs/readme.txt": "Subdirectory content."})
    extract_archive(zip3_path, out3_path)
    print("-" * 20)

    # Test Case 4: Non-existent archive
    print("--- Test Case 4: Non-existent archive ---")
    non_existent_path = os.path.join(test_dir, "ghost.zip")
    out4_path = os.path.join(output_dir, "test4")
    extract_archive(non_existent_path, out4_path)
    print("-" * 20)

    # Test Case 5: Not an archive file
    print("--- Test Case 5: Not an archive file ---")
    not_archive_path = os.path.join(test_dir, "plain.txt")
    out5_path = os.path.join(output_dir, "test5")
    with open(not_archive_path, "w") as f:
        f.write("I am not a zip or tar file.")
    extract_archive(not_archive_path, out5_path)
    print("-" * 20)
    
    # Cleanup
    print("Cleaning up test files and directories...")
    shutil.rmtree(test_dir)
    print("Cleanup complete.")

if __name__ == "__main__":
    main()