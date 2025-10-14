import os
import sys

def delete_file(file_path):
    """
    Deletes a file specified by the file path.
    :param file_path: The path to the file to be deleted.
    """
    if not file_path or not isinstance(file_path, str):
        print("Error: File path must be a non-empty string.", file=sys.stderr)
        return

    try:
        # os.remove() deletes a file. It raises an error if path is a directory.
        os.remove(file_path)
        print(f"Success: File '{file_path}' was deleted successfully.")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
    except PermissionError:
        print(f"Security Error: Permission denied to delete '{file_path}'.", file=sys.stderr)
    except IsADirectoryError:
        print(f"Error: Path '{file_path}' is a directory, not a file.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)

def run_test_cases():
    """Sets up and runs a series of test cases."""
    print("--- Running Test Cases ---")
    test_file1 = "test1.tmp"
    test_file2 = "test2.tmp"
    non_existent_file = "nonexistent.tmp"
    already_deleted_file = "test1.tmp"
    test_dir = "testdir.tmp"

    # Setup test files and directory
    try:
        with open(test_file1, 'w') as f: pass
        with open(test_file2, 'w') as f: pass
        if not os.path.exists(test_dir):
            os.mkdir(test_dir)
    except OSError as e:
        print(f"Failed to setup test cases: {e}", file=sys.stderr)
        return

    # Test Case 1: Delete an existing file
    print("\n[Test Case 1: Delete an existing file]")
    delete_file(test_file1)

    # Test Case 2: Delete another existing file
    print("\n[Test Case 2: Delete another existing file]")
    delete_file(test_file2)

    # Test Case 3: Attempt to delete a non-existent file
    print("\n[Test Case 3: Attempt to delete a non-existent file]")
    delete_file(non_existent_file)

    # Test Case 4: Attempt to delete a file that was already deleted
    print("\n[Test Case 4: Attempt to delete an already deleted file]")
    delete_file(already_deleted_file)

    # Test Case 5: Attempt to delete a directory
    print("\n[Test Case 5: Attempt to delete a directory]")
    delete_file(test_dir)
    
    # Cleanup the test directory
    if os.path.exists(test_dir):
        os.rmdir(test_dir)

    print("\n--- Test Cases Finished ---")


if __name__ == "__main__":
    run_test_cases()
    
    # --- Main Logic for Command Line ---
    if len(sys.argv) > 1:
        print("\n--- Deleting file from command line argument ---")
        delete_file(sys.argv[1])
    else:
        script_name = os.path.basename(sys.argv[0])
        print(f"\nUsage: python {script_name} <file_path_to_delete>")
        print(f"Example: python {script_name} my_file.txt")