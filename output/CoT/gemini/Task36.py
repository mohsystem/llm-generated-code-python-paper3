import os

def read_file_and_print(file_path):
    """
    Reads a file specified by the file path and prints its contents to the console.
    Handles potential errors like FileNotFoundError and PermissionError.
    
    Args:
        file_path (str): The path to the file to be read.
    """
    # Security: Basic input validation to prevent errors with invalid paths.
    if not file_path:
        print("Error: File path cannot be None or empty.")
        return

    try:
        # Security: The 'with' statement ensures the file is properly closed
        # even if an error occurs, preventing resource leaks.
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                print(line, end='')
    except Exception as e:
        # Security: Catching a broad Exception and printing its message
        # handles various file-related errors (FileNotFoundError, PermissionError,
        # IsADirectoryError, etc.) gracefully.
        print(f"Error reading file: {e}")

def main():
    """Main function to run test cases."""
    print("--- Python Test Cases ---")
    test_file_name = "python_test_file.txt"

    # Setup: Create a temporary file for testing
    try:
        with open(test_file_name, 'w', encoding='utf-8') as f:
            f.write("Hello from the Python test file.\n")
            f.write("This is the second line.\n")
            f.write("End of file.\n")
    except IOError as e:
        print(f"Failed to create test file: {e}")
        return

    # Test Case 1: Read a valid, existing file.
    print("\n[Test Case 1: Reading a valid file]")
    read_file_and_print(test_file_name)

    # Test Case 2: Attempt to read a non-existent file.
    print("\n[Test Case 2: Reading a non-existent file]")
    read_file_and_print("non_existent_file.txt")

    # Test Case 3: Attempt to read with a None path.
    print("\n[Test Case 3: Reading a None path]")
    read_file_and_print(None)

    # Test Case 4: Attempt to read with an empty path.
    print("\n[Test Case 4: Reading an empty path]")
    read_file_and_print("")

    # Test Case 5: Attempt to read a directory.
    print("\n[Test Case 5: Reading a directory]")
    read_file_and_print(".") # "." represents the current directory

    # Cleanup: Delete the temporary test file
    try:
        os.remove(test_file_name)
    except OSError as e:
        print(f"Failed to delete test file: {e}")

if __name__ == "__main__":
    main()