import os
import shutil

# A predefined base directory to prevent access to other parts of the filesystem.
IMAGE_BASE_DIRECTORY = "test_images"

def img(filename: str) -> bytes | None:
    """
    Simulates fetching an image file based on a 'file' parameter.
    This function securely reads a file from a predefined base directory,
    preventing path traversal attacks.

    Args:
        filename: The name of the file requested. This should be a simple
                  filename without any path components.
    
    Returns:
        A bytes object containing the file's data, or None if the file
        cannot be read or the request is invalid/unsafe.
    """
    if not filename:
        print("Error: Filename is null or empty.")
        return None

    # Security Step 1: Sanitize the filename to remove any directory information.
    # os.path.basename() is a crucial function for this.
    sanitized_filename = os.path.basename(filename)
    if sanitized_filename != filename:
        print(f"Security Error: Potentially unsafe filename detected: '{filename}'")
        return None

    # Security Step 2: Create a full path and resolve it to a canonical path.
    base_dir_real_path = os.path.realpath(IMAGE_BASE_DIRECTORY)
    file_path = os.path.join(base_dir_real_path, sanitized_filename)
    
    # Security Step 3: Verify that the resolved path is within the base directory.
    # This is the primary defense against path traversal attacks (e.g., "../").
    if os.path.commonpath([base_dir_real_path]) != os.path.commonpath([base_dir_real_path, file_path]):
        print(f"Security Error: Path traversal attempt detected for file: '{filename}'")
        return None

    if not os.path.isfile(file_path):
        print(f"Error: File not found or is not a regular file: {file_path}")
        return None

    try:
        # Open the file in read binary mode ('rb')
        with open(file_path, 'rb') as f:
            return f.read()
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def main():
    """Main function with test cases"""
    # --- Test Setup ---
    try:
        if os.path.exists(IMAGE_BASE_DIRECTORY):
            shutil.rmtree(IMAGE_BASE_DIRECTORY)
        if os.path.exists("secret.txt"):
            os.remove("secret.txt")
            
        os.makedirs(IMAGE_BASE_DIRECTORY, exist_ok=True)
        with open(os.path.join(IMAGE_BASE_DIRECTORY, "test1.jpg"), "wb") as f:
            f.write(b"ImageData1")
        with open("secret.txt", "wb") as f:
            f.write(b"SecretData")
        print("Test environment set up.")
    except Exception as e:
        print(f"Failed to set up test environment: {e}")
        return

    print("\n--- Running Test Cases ---")

    # Test Case 1: Valid file
    print("Test 1: Requesting a valid file 'test1.jpg'")
    data1 = img("test1.jpg")
    if data1 == b"ImageData1":
        print("  Result: SUCCESS, content matches.")
    else:
        print("  Result: FAILED.")

    # Test Case 2: Non-existent file
    print("\nTest 2: Requesting a non-existent file 'notfound.jpg'")
    data2 = img("notfound.jpg")
    if data2 is None:
        print("  Result: SUCCESS, function returned None as expected.")
    else:
        print("  Result: FAILED.")

    # Test Case 3: Path traversal attempt
    print("\nTest 3: Path traversal attempt '../secret.txt'")
    data3 = img("../secret.txt")
    if data3 is None:
        print("  Result: SUCCESS, path traversal blocked.")
    else:
        print("  Result: FAILED.")

    # Test Case 4: Path traversal with directory in name
    print("\nTest 4: Path traversal attempt 'fake_dir/../../secret.txt'")
    data4 = img("fake_dir/../../secret.txt")
    if data4 is None:
        print("  Result: SUCCESS, path traversal blocked.")
    else:
        print("  Result: FAILED.")

    # Test Case 5: Absolute path attempt
    abs_path_to_secret = os.path.abspath("secret.txt")
    print(f"\nTest 5: Absolute path attempt '{abs_path_to_secret}'")
    data5 = img(abs_path_to_secret)
    if data5 is None:
        print("  Result: SUCCESS, absolute path blocked.")
    else:
        print("  Result: FAILED.")

    # --- Test Cleanup ---
    try:
        shutil.rmtree(IMAGE_BASE_DIRECTORY)
        os.remove("secret.txt")
        print("\n--- Test environment cleaned up. ---")
    except Exception as e:
        print(f"Failed to clean up test environment: {e}")

if __name__ == "__main__":
    main()