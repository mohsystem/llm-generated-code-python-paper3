import os
import shutil
import re

MAX_FILE_SIZE = 10 * 1024 * 1024 # 10 MB
ALLOWED_EXTENSIONS = ['.txt', '.jpg', '.png', '.pdf']

def secure_file_upload(source_path, dest_dir):
    """
    Securely uploads a file by copying it from a source path to a destination directory
    with several security checks.
    
    :param source_path: The path to the source file.
    :param dest_dir: The path to the destination directory.
    :return: True if the upload was successful, False otherwise.
    """
    try:
        # 1. Source File Checks
        if not os.path.exists(source_path) or not os.path.isfile(source_path):
            print("Error: Source file does not exist or is not a file.")
            return False
        
        # 2. Destination Directory Checks
        if not os.path.exists(dest_dir) or not os.path.isdir(dest_dir):
            print("Error: Destination directory does not exist.")
            return False
        if not os.access(dest_dir, os.W_OK):
            print("Error: Destination directory is not writable.")
            return False

        # 3. File Size Check
        file_size = os.path.getsize(source_path)
        if file_size > MAX_FILE_SIZE:
            print(f"Error: File size exceeds the maximum limit of {MAX_FILE_SIZE // (1024*1024)} MB.")
            return False

        # 4. Filename and Extension Validation
        filename = os.path.basename(source_path)
        
        # Sanitize filename: reject if it contains path separators.
        if "/" in filename or "\\" in filename:
            print("Error: Filename contains invalid path characters.")
            return False

        # A more restrictive sanitization can be used if needed:
        # sanitized_filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)

        if not any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
            print("Error: File extension is not allowed.")
            return False

        # 5. Path Traversal Check
        # Get the real, canonical path of the destination directory
        real_dest_dir = os.path.realpath(dest_dir)
        
        # Construct the full destination path
        dest_path = os.path.join(real_dest_dir, filename)
        
        # Get the real path of the final file destination and its directory
        real_dest_path_dir = os.path.dirname(os.path.realpath(dest_path))

        # Check if the final file path is within the destination directory
        if real_dest_path_dir != real_dest_dir:
            print("Error: Path traversal attempt detected.")
            return False

        # 6. Check for existing file
        final_dest_path = os.path.join(real_dest_dir, filename)
        if os.path.exists(final_dest_path):
            print("Error: File with the same name already exists in the destination.")
            return False

        # 7. Perform the copy
        shutil.copy2(source_path, final_dest_path)
        print(f"Success: File '{filename}' uploaded successfully.")
        return True
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def main():
    """ Main function with test cases """
    # Setup for tests
    upload_dir = "uploads_python"
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)

    # Create test files
    with open("test_good.txt", "w") as f:
        f.write("This is a good file.")
    with open("test_large.bin", "wb") as f:
        f.write(b'\0' * (MAX_FILE_SIZE + 1))
    with open("test_bad.exe", "w") as f:
        f.write("dummy executable")
    with open("traversal_test.txt", "w") as f:
        f.write("This file should not escape the upload dir")


    print("--- Running Test Cases ---")

    # Test Case 1: Successful upload
    print("\n[Test 1] Successful Upload:")
    secure_file_upload("test_good.txt", upload_dir)

    # Test Case 2: File already exists (Overwrite prevention)
    print("\n[Test 2] File Exists:")
    secure_file_upload("test_good.txt", upload_dir)

    # Test Case 3: File too large
    print("\n[Test 3] File Too Large:")
    secure_file_upload("test_large.bin", upload_dir)

    # Test Case 4: Disallowed extension
    print("\n[Test 4] Disallowed Extension:")
    secure_file_upload("test_bad.exe", upload_dir)

    # Test Case 5: Path Traversal Attempt
    print("\n[Test 5] Path Traversal Attempt:")
    malicious_dest_dir = os.path.join(upload_dir, "..")
    secure_file_upload("traversal_test.txt", malicious_dest_dir)

    # Cleanup
    os.remove("test_good.txt")
    os.remove("test_large.bin")
    os.remove("test_bad.exe")
    os.remove("traversal_test.txt")

if __name__ == "__main__":
    main()