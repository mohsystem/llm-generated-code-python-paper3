import os
import sys

# Define a maximum file size to prevent resource exhaustion (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

def read_file_content(file_path):
    """
    Reads the content of a file after performing security checks.

    :param file_path: The path to the file provided by the user.
    :return: The content of the file as a string, or an error message.
    """
    if not file_path:
        return "Error: File path cannot be empty."

    try:
        # Security Check 1: Path Traversal
        # Resolve the real, canonical path to prevent directory traversal.
        # For a real application, this should be a specific, whitelisted "jail" directory.
        base_dir = os.path.realpath(os.getcwd())
        real_path = os.path.realpath(file_path)

        if not real_path.startswith(base_dir):
            return f"Error: Path Traversal attempt detected. Access is restricted to {base_dir}."

        # Security Check 2: Existence and Type
        if not os.path.exists(real_path):
            return f"Error: File does not exist at path: {real_path}"
        if not os.path.isfile(real_path):
            return "Error: Path points to a directory, not a file."
        
        # Security Check 3: File Size
        file_size = os.path.getsize(real_path)
        if file_size > MAX_FILE_SIZE:
            return f"Error: File size exceeds the maximum limit of {MAX_FILE_SIZE} bytes."

        # Read file content
        with open(real_path, 'r', encoding='utf-8') as f:
            return f.read()

    except PermissionError:
        return "Error: Permission denied. Cannot read the file."
    except Exception as e:
        return f"Error: An unexpected error occurred - {e}"

def run_test_cases():
    """Sets up and runs a suite of test cases."""
    print("No command-line argument provided. Running test cases...")
    test_dir = "test_dir_python"
    valid_file_path = os.path.join(test_dir, "test_valid.txt")
    
    # Setup
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    with open(valid_file_path, "w") as f:
        f.write("This is a valid test file.")

    # Test Case 1: Read a valid file
    print("\n--- Test Case 1: Valid File ---")
    print(f"Path: {valid_file_path}")
    print(f"Result: {read_file_content(valid_file_path)}")

    # Test Case 2: File not found
    print("\n--- Test Case 2: Non-existent File ---")
    non_existent_path = os.path.join(test_dir, "non_existent.txt")
    print(f"Path: {non_existent_path}")
    print(f"Result: {read_file_content(non_existent_path)}")

    # Test Case 3: Path Traversal attempt
    print("\n--- Test Case 3: Path Traversal ---")
    traversal_path = os.path.join(test_dir, "..", test_dir, os.path.basename(valid_file_path))
    print(f"Path: {traversal_path}")
    print(f"Result: {read_file_content(traversal_path)}")

    # Test Case 4: Reading a directory
    print("\n--- Test Case 4: Reading a Directory ---")
    print(f"Path: {test_dir}")
    print(f"Result: {read_file_content(test_dir)}")
    
    # Test Case 5: File too large
    print("\n--- Test Case 5: File Too Large ---")
    global MAX_FILE_SIZE
    original_max_size = MAX_FILE_SIZE
    MAX_FILE_SIZE = 10 # Set a tiny limit for the test
    print(f"Path: {valid_file_path} (with max size = {MAX_FILE_SIZE} bytes)")
    print(f"Result: {read_file_content(valid_file_path)}")
    MAX_FILE_SIZE = original_max_size # Reset

    # Cleanup
    if os.path.exists(valid_file_path):
        os.remove(valid_file_path)
    if os.path.exists(test_dir):
        os.rmdir(test_dir)
    print("\nTest cleanup complete.")


if __name__ == "__main__":
    # If a command-line argument is provided, use it.
    if len(sys.argv) == 2:
        filepath = sys.argv[1]
        print(f"Reading file from command line argument: {filepath}")
        content = read_file_content(filepath)
        print("--- File Content ---")
        print(content)
        print("--- End of Content ---")
    else:
        # Otherwise, run the built-in test cases.
        run_test_cases()