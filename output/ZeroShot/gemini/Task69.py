import os
import sys

def delete_file_securely(file_path):
    """
    Securely deletes a file after validating the path.
    The file must exist, be a regular file, and be located within the current working directory or its subdirectories.
    This prevents path traversal attacks (e.g., using "../") to delete files outside the intended scope.

    :param file_path: The path to the file to be deleted.
    :return: True if the file was successfully deleted, False otherwise.
    """
    if not file_path:
        print("Error: File path is null or empty.", file=sys.stderr)
        return False
    
    try:
        # Security Check 1: Canonicalize paths to resolve '..' and symbolic links.
        # Use realpath to get the canonical path of the file and the current working directory.
        cwd_real_path = os.path.realpath(os.getcwd())
        file_real_path = os.path.realpath(file_path)

        # Security Check 2: Ensure the file path is within the current working directory.
        if not file_real_path.startswith(cwd_real_path):
            print(f"Error: Path traversal attempt detected. Cannot delete files outside the current directory: {file_path}", file=sys.stderr)
            return False

        # Validation Check 1: Ensure the path points to an existing file.
        # This check is implicitly handled by os.path.isfile, but we make it explicit.
        if not os.path.exists(file_path):
             print(f"Error: File does not exist: {file_path}", file=sys.stderr)
             return False

        # Validation Check 2: Ensure it's a file and not a directory.
        if not os.path.isfile(file_path):
            print(f"Error: Path does not point to a regular file (it might be a directory): {file_path}", file=sys.stderr)
            return False
            
        # Attempt to delete the file.
        os.remove(file_path)
        print(f"Successfully deleted file: {file_path}")
        return True

    except FileNotFoundError:
        print(f"Error: File does not exist: {file_path}", file=sys.stderr)
        return False
    except PermissionError:
        print(f"Error: Permission denied to delete file: {file_path}", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Error processing path: {e}", file=sys.stderr)
        return False

def run_test_cases():
    """Sets up a test environment, runs test cases, and cleans up."""
    print("\n--- Running Python Test Cases ---")
    safe_file = "test_safe.txt"
    test_dir = "test_dir"
    unsafe_file = os.path.join("..", "test_unsafe.txt")

    # Setup test environment
    try:
        with open(safe_file, 'w') as f:
            f.write("test")
        os.makedirs(test_dir, exist_ok=True)
        print("Test environment created.")
    except OSError as e:
        print(f"Failed to set up test environment: {e}", file=sys.stderr)
        return
        
    # Run tests
    try:
        # Test 1: Success case - delete a safe file
        print("\n[Test 1] Deleting a safe local file...")
        delete_file_securely(safe_file)

        # Test 2: Failure case - file does not exist
        print("\n[Test 2] Deleting a non-existent file...")
        delete_file_securely("nonexistent.txt")

        # Test 3: Failure case - attempting to delete a directory
        print("\n[Test 3] Deleting a directory...")
        delete_file_securely(test_dir)

        # Test 4: Failure case - path traversal
        print("\n[Test 4] Attempting path traversal deletion...")
        delete_file_securely(unsafe_file)
        
        # Test 5: Failure case - absolute path
        print("\n[Test 5] Attempting to delete file with an absolute path...")
        # Create a temporary file to test absolute path deletion
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            abs_path = tmp.name
        delete_file_securely(abs_path)
        if os.path.exists(abs_path): # Cleanup the temp file if deletion failed as expected
            os.remove(abs_path)
            
    finally:
        # Cleanup test environment
        if os.path.exists(safe_file):
            os.remove(safe_file)
        if os.path.isdir(test_dir):
            os.rmdir(test_dir)
        print("\nTest environment cleaned up.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(f"Attempting to delete file from command line argument: {sys.argv[1]}")
        delete_file_securely(sys.argv[1])
    else:
        print("No command line arguments provided. Running test cases...")
        run_test_cases()