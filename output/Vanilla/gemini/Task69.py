import os
import sys

def delete_file(file_path):
    """
    Deletes the file at the specified path.
    Args:
        file_path (str): The path of the file to delete.
    Returns:
        bool: True if the file was deleted successfully, False otherwise.
    """
    try:
        # Check if the file exists before attempting to delete.
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        else:
            # File does not exist.
            return False
    except OSError as e:
        # Handles errors like permission denied.
        print(f"  [Error] {e.strerror} - {e.filename}", file=sys.stderr)
        return False

def run_test_cases():
    """Creates and runs 5 test cases for the delete_file function."""
    print("No command line arguments provided. Running test cases...")
    test_files = [f"test{i}.tmp" for i in range(1, 6)]
    
    # Test Cases 1-5: Create and then delete a file.
    for i, file_name in enumerate(test_files, 1):
        print(f"\n--- Test Case {i}: Delete {file_name} ---")
        
        # 1. Create a dummy file for the test.
        try:
            with open(file_name, 'w') as f:
                pass
            print(f"  [Setup] Created temporary file: {file_name}")
        except IOError as e:
            print(f"  [Setup] Error creating file: {e}", file=sys.stderr)
            continue # Skip test if setup fails

        # 2. Attempt to delete the file.
        if delete_file(file_name):
            print("  [Result] SUCCESS: File deleted.")
        else:
            print("  [Result] FAILED: File not deleted.")

def main():
    """
    Main entry point. Handles command line arguments or runs test cases.
    """
    # If a command-line argument is provided, use it as the file path.
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"Attempting to delete file from command line: {file_path}")
        if delete_file(file_path):
            print("File deleted successfully.")
        else:
            print("Failed to delete the file. It may not exist or you may not have permission.")
    else:
        # If no arguments, run the built-in test cases.
        run_test_cases()

if __name__ == "__main__":
    main()