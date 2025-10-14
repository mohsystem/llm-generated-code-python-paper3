import os
import zipfile
import tarfile
import tempfile
import shutil

def _unzip_safe(zip_path, dest_dir):
    """
    Safely extracts a ZIP file to a destination directory, preventing path traversal.
    """
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # Get the absolute path of the destination directory
        dest_dir_abs = os.path.realpath(dest_dir)
        
        for member_info in zip_ref.infolist():
            target_path = os.path.join(dest_dir, member_info.filename)
            target_path_abs = os.path.realpath(target_path)
            
            # Security Check: Ensure the member path is within the destination directory
            if not target_path_abs.startswith(dest_dir_abs):
                print(f"Path Traversal attempt detected. Skipping: {member_info.filename}")
                continue
            
            # Extract only this member
            zip_ref.extract(member_info, dest_dir)
    return True

def _untar_safe(tar_path, dest_dir):
    """
    Safely extracts a TAR file to a destination directory, preventing path traversal.
    """
    with tarfile.open(tar_path, 'r:*') as tar_ref:
        dest_dir_abs = os.path.realpath(dest_dir)

        # In Python 3.12+, you can use the built-in filter='data' for safety.
        # This is a manual implementation for compatibility with older versions.
        for member_info in tar_ref.getmembers():
            target_path = os.path.join(dest_dir, member_info.name)
            
            # Using os.path.abspath is sufficient here as we check before creation.
            # realpath would fail on broken symlinks which might be part of the tar.
            target_path_abs = os.path.abspath(target_path)

            if not target_path_abs.startswith(dest_dir_abs):
                print(f"Path Traversal attempt detected. Skipping: {member_info.name}")
                continue
            
            tar_ref.extract(member_info, dest_dir, numeric_owner=True)
    return True

def extract_archive(archive_path, dest_dir):
    """
    Extracts an archive file (ZIP or TAR) to a destination directory.
    Determines the archive type by its extension.

    Args:
        archive_path (str): The path to the archive file.
        dest_dir (str): The directory to extract the files into.

    Returns:
        bool: True on success, False on failure.
    """
    if not os.path.exists(archive_path):
        print(f"Error: Archive not found at '{archive_path}'")
        return False
        
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir, exist_ok=True)

    try:
        if archive_path.endswith('.zip'):
            return _unzip_safe(archive_path, dest_dir)
        elif archive_path.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2')):
            return _untar_safe(archive_path, dest_dir)
        else:
            print(f"Error: Unsupported archive format for '{archive_path}'")
            return False
    except (zipfile.BadZipFile, tarfile.TarError, IOError) as e:
        print(f"Error extracting archive '{archive_path}': {e}")
        return False

# --- Test Cases ---
def main():
    with tempfile.TemporaryDirectory() as base_test_dir:
        print(f"Running tests in: {base_test_dir}")

        # --- Test Case 1: Normal ZIP Extraction ---
        print("\n--- Test Case 1: Normal ZIP Extraction ---")
        normal_zip = os.path.join(base_test_dir, "normal.zip")
        extract_dir1 = os.path.join(base_test_dir, "extract1")
        with zipfile.ZipFile(normal_zip, 'w') as zf:
            zf.writestr("dir1/file1.txt", "content1")
            zf.writestr("file2.txt", "content2")
        success = extract_archive(normal_zip, extract_dir1)
        print(f"Extraction successful: {success}")
        print(f"Exists 'extract1/dir1/file1.txt': {os.path.exists(os.path.join(extract_dir1, 'dir1', 'file1.txt'))}")

        # --- Test Case 2: Normal TAR Extraction ---
        print("\n--- Test Case 2: Normal TAR Extraction ---")
        normal_tar = os.path.join(base_test_dir, "normal.tar.gz")
        extract_dir2 = os.path.join(base_test_dir, "extract2")
        with tarfile.open(normal_tar, 'w:gz') as tf:
            # We need to create TarInfo objects to add files from strings
            import io, time
            data = b"tar content"
            tarinfo = tarfile.TarInfo(name="file.txt")
            tarinfo.size = len(data)
            tarinfo.mtime = time.time()
            tf.addfile(tarinfo, io.BytesIO(data))
        success = extract_archive(normal_tar, extract_dir2)
        print(f"Extraction successful: {success}")
        print(f"Exists 'extract2/file.txt': {os.path.exists(os.path.join(extract_dir2, 'file.txt'))}")
        
        # --- Test Case 3: Malicious ZIP with Path Traversal ---
        print("\n--- Test Case 3: Malicious ZIP Extraction ---")
        malicious_zip = os.path.join(base_test_dir, "malicious.zip")
        extract_dir3 = os.path.join(base_test_dir, "extract3")
        with zipfile.ZipFile(malicious_zip, 'w') as zf:
            zf.writestr("../../malicious.txt", "evil content")
        success = extract_archive(malicious_zip, extract_dir3)
        print(f"Extraction operation finished: {success}")
        # The malicious file should NOT be in the parent of base_test_dir
        malicious_file_path = os.path.join(base_test_dir, "..", "malicious.txt")
        print(f"Malicious file created outside test dir: {os.path.exists(malicious_file_path)}")
        
        # --- Test Case 4: Extracting to a non-existent directory ---
        print("\n--- Test Case 4: Extract to Non-Existent Directory ---")
        extract_dir4 = os.path.join(base_test_dir, "new_dir_extract")
        success = extract_archive(normal_zip, extract_dir4)
        print(f"Extraction successful: {success}")
        print(f"Exists 'new_dir_extract/file2.txt': {os.path.exists(os.path.join(extract_dir4, 'file2.txt'))}")

        # --- Test Case 5: Archive path does not exist ---
        print("\n--- Test Case 5: Archive Path Not Found ---")
        non_existent_zip = os.path.join(base_test_dir, "notfound.zip")
        extract_dir5 = os.path.join(base_test_dir, "extract5")
        success = extract_archive(non_existent_zip, extract_dir5)
        print(f"Extraction successful: {success}")

if __name__ == "__main__":
    main()