import os
import shutil

SAFE_DIRECTORY_NAME = "safe_dir"

def read_file_from_safe_directory(filename):
    """
    Securely reads a file from a predefined safe directory.
    Prevents path traversal attacks by resolving the real path and verifying
    it is a subpath of the safe directory's real path.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: The content of the file if successful, otherwise None.
    """
    if not filename or '\0' in filename:
        print("Error: Filename is invalid (empty, None, or contains null byte).")
        return None

    try:
        # Get the absolute, canonical path of the safe directory
        safe_dir_path = os.path.realpath(SAFE_DIRECTORY_NAME)
        
        # Construct the full path to the target file
        # os.path.join prevents some simple attacks but is not enough by itself
        target_path = os.path.join(safe_dir_path, filename)
        
        # Get the absolute, canonical path of the target file
        real_target_path = os.path.realpath(target_path)
        
        # The crucial security check: is the real path of the target
        # within the real path of the safe directory?
        if os.path.commonpath([real_target_path, safe_dir_path]) != safe_dir_path:
            print(f"Security Error: Path traversal attempt detected for file: {filename}")
            return None
        
        if not os.path.isfile(real_target_path):
            print(f"Error: Path does not point to a regular file: {filename}")
            return None

        with open(real_target_path, 'r', encoding='utf-8') as f:
            return f.read()
            
    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred for file '{filename}': {e}")
        return None

def setup_test_environment():
    """Sets up the directories and files needed for testing."""
    print("--- Setting up test environment ---")
    try:
        # Create safe directory
        os.makedirs(SAFE_DIRECTORY_NAME, exist_ok=True)
        # Create subdirectory
        os.makedirs(os.path.join(SAFE_DIRECTORY_NAME, "subdir"), exist_ok=True)
        
        # Create valid files
        with open(os.path.join(SAFE_DIRECTORY_NAME, "test1.txt"), "w") as f:
            f.write("This is a safe file.")
        with open(os.path.join(SAFE_DIRECTORY_NAME, "subdir", "test2.txt"), "w") as f:
            f.write("This is another safe file in a subdirectory.")
            
        # Create a file outside the safe directory
        with open("secret.txt", "w") as f:
            f.write("This is a secret file.")
        print("Setup complete.")
    except Exception as e:
        print(f"Failed to set up test environment: {e}")


def cleanup_test_environment():
    """Removes the directories and files created for testing."""
    print("\n--- Cleaning up test environment ---")
    try:
        if os.path.isdir(SAFE_DIRECTORY_NAME):
            shutil.rmtree(SAFE_DIRECTORY_NAME)
        if os.path.exists("secret.txt"):
            os.remove("secret.txt")
        print("Cleanup complete.")
    except Exception as e:
        print(f"Failed to clean up test environment: {e}")

def main():
    """Main function to run test cases."""
    setup_test_environment()
    print("\n--- Running Test Cases ---")

    # Test Case 1: Read a valid file
    print("\n[Test 1] Reading a valid file 'test1.txt'")
    content = read_file_from_safe_directory("test1.txt")
    if content:
        print(f"SUCCESS. Content: {content}")
    else:
        print("FAILED.")

    # Test Case 2: Read a non-existent file
    print("\n[Test 2] Reading a non-existent file 'nonexistent.txt'")
    content = read_file_from_safe_directory("nonexistent.txt")
    if not content:
        print("FAILED. (Expected)")

    # Test Case 3: Path traversal attempt
    print("\n[Test 3] Path traversal attempt '../secret.txt'")
    content = read_file_from_safe_directory("../secret.txt")
    if not content:
        print("FAILED. (Expected Security Block)")
    
    # Test Case 4: Path traversal from a subdirectory
    print("\n[Test 4] Path traversal from subdirectory 'subdir/../../secret.txt'")
    content = read_file_from_safe_directory("subdir/../../secret.txt")
    if not content:
        print("FAILED. (Expected Security Block)")

    # Test Case 5: Reading a valid file in a subdirectory
    print("\n[Test 5] Reading a valid file in a subdirectory 'subdir/test2.txt'")
    content = read_file_from_safe_directory("subdir/test2.txt")
    if content:
        print(f"SUCCESS. Content: {content}")
    else:
        print("FAILED.")

    cleanup_test_environment()

if __name__ == "__main__":
    main()