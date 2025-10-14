import os
import shutil

def upload_file(source_file_path, destination_path):
    """
    Simulates a file upload by copying a file from a source path to a destination path.
    The destination path can be a directory or a full file path.
    
    :param source_file_path: The path to the file to be "uploaded".
    :param destination_path: The directory or full path where the file will be saved.
    :return: True if the upload (copy) was successful, False otherwise.
    """
    if not os.path.exists(source_file_path):
        print(f"Error: Source file does not exist: {source_file_path}")
        return False
        
    try:
        # If destination is a directory, ensure it exists
        dest_dir = os.path.dirname(destination_path)
        if os.path.isdir(destination_path): # If destination is a directory itself
             dest_dir = destination_path

        if dest_dir and not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
            print(f"Created directory: {dest_dir}")
        
        # shutil.copy2 preserves metadata
        shutil.copy2(source_file_path, destination_path)
        print(f"File uploaded successfully from '{source_file_path}' to '{destination_path}'")
        return True
    except (IOError, os.error) as e:
        print(f"File upload failed: {e}")
        return False

# Main block with test cases
if __name__ == "__main__":
    # Setup for test cases
    test_dir = "python_upload_test_dir"
    source_file = "python_source.txt"
    
    # Create a dummy source file
    with open(source_file, "w") as f:
        f.write("This is a python test file for upload.")
        
    # Create destination directory
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
        
    print("--- Running Test Cases ---")

    # Test Case 1: Successful upload to a directory
    print("\n--- Test Case 1: Successful Upload to Directory ---")
    upload_file(source_file, test_dir)

    # Test Case 2: Uploading a non-existent source file
    print("\n--- Test Case 2: Non-existent Source File ---")
    upload_file("non_existent_file.txt", test_dir)

    # Test Case 3: Overwriting an existing file (by specifying full path)
    print("\n--- Test Case 3: Overwriting an Existing File ---")
    overwrite_file_path = os.path.join(test_dir, "overwrite.txt")
    upload_file(source_file, overwrite_file_path) # First time
    print("Uploading again to the same destination...")
    upload_file(source_file, overwrite_file_path) # Second time

    # Test Case 4: Uploading to a nested directory that doesn't exist
    print("\n--- Test Case 4: Upload to a non-existent nested directory ---")
    nested_dest_path = os.path.join(test_dir, "new", "nested", "uploaded_file4.txt")
    upload_file(source_file, nested_dest_path)

    # Test Case 5: Uploading to a destination with a different name
    print("\n--- Test Case 5: Uploading with a new filename ---")
    new_name_path = os.path.join(test_dir, "renamed_file.txt")
    upload_file(source_file, new_name_path)

    # Cleanup
    print("\n--- Cleaning up test files and directories ---")
    if os.path.exists(source_file):
        os.remove(source_file)
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    print("Cleanup complete.")