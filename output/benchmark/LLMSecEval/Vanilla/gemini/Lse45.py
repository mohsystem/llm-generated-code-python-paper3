import os
import shutil

SAFE_DIR = "safe_dir"

def read_file_from_safe_dir(filename: str) -> str:
    """
    Reads the content of a file from a predefined safe directory.
    Prevents directory traversal attacks.

    :param filename: The name of the file to read.
    :return: The content of the file as a string, or an error message.
    """
    if not filename:
        return "Error: Filename cannot be empty."

    # Basic check for path components in the filename itself
    if os.path.isabs(filename) or ".." in filename.split(os.path.sep):
        return "Error: Directory traversal attempt detected."

    try:
        # Get absolute paths for security check
        safe_dir_abs = os.path.abspath(SAFE_DIR)
        requested_path_abs = os.path.abspath(os.path.join(safe_dir_abs, filename))

        # Security Check: Ensure the requested path is within the safe directory
        if os.path.commonprefix([requested_path_abs, safe_dir_abs]) != safe_dir_abs:
            return "Error: Directory traversal attempt detected."

        if not os.path.exists(requested_path_abs):
            return f"Error: File not found: {filename}"
        
        if not os.path.isfile(requested_path_abs):
            return f"Error: Requested path is not a file."

        with open(requested_path_abs, 'r', encoding='utf-8') as f:
            return f.read()

    except Exception as e:
        return f"Error: Could not read file: {e}"

def setup_test_environment():
    """Sets up a test environment with a safe directory and some files."""
    if os.path.exists(SAFE_DIR):
        shutil.rmtree(SAFE_DIR)
    os.makedirs(SAFE_DIR)
    with open(os.path.join(SAFE_DIR, "file1.txt"), "w") as f:
        f.write("This is file 1 from Python.")
    with open(os.path.join(SAFE_DIR, "file2.txt"), "w") as f:
        f.write("Content of the second file.")
    print(f"Test environment created in './{SAFE_DIR}'")

def main():
    """Main function to run test cases."""
    setup_test_environment()
    print("\n--- Running Python Test Cases ---")

    # Test Case 1: Read a valid file
    print("1. Reading 'file1.txt':")
    print(f"   Result: {read_file_from_safe_dir('file1.txt')}\n")

    # Test Case 2: Read another valid file
    print("2. Reading 'file2.txt':")
    print(f"   Result: {read_file_from_safe_dir('file2.txt')}\n")

    # Test Case 3: Attempt to read a non-existent file
    print("3. Reading 'nonexistent.txt':")
    print(f"   Result: {read_file_from_safe_dir('nonexistent.txt')}\n")

    # Test Case 4: Attempt directory traversal (simple)
    print("4. Attempting to read '../some_file.txt':")
    print(f"   Result: {read_file_from_safe_dir('../some_file.txt')}\n")

    # Test Case 5: Attempt directory traversal (nested)
    print("5. Attempting to read '..\\..\\some_file.txt':")
    print(f"   Result: {read_file_from_safe_dir(os.path.join('..','..','some_file.txt'))}\n")


if __name__ == "__main__":
    main()