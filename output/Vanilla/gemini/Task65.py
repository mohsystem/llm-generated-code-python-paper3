import os
import sys

def read_file_content(filename):
    """
    Retrieves a filename, validates it, and returns the file's content.

    Args:
        filename (str): The name of the file to read.

    Returns:
        str: A string containing the file content or an error message.
    """
    if not filename or not isinstance(filename, str) or filename.strip() == "":
        return "Error: Filename cannot be None or empty."

    if not os.path.exists(filename):
        return f"Error: File does not exist: {filename}"
    
    if os.path.isdir(filename):
        return f"Error: Path points to a directory, not a file: {filename}"

    if not os.access(filename, os.R_OK):
        return f"Error: Cannot read file (permission denied): {filename}"

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except IOError as e:
        return f"Error: An I/O error occurred while reading the file: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def main():
    """Main function to run tests and handle command line arguments."""
    # Example with command-line arguments
    if len(sys.argv) > 1:
        print("--- Reading from command line argument ---")
        filename = sys.argv[1]
        print(f"Reading file: {filename}")
        content = read_file_content(filename)
        print(f"Content:\n{content}")
        print("----------------------------------------\n")
    else:
        print(f"Usage: python {sys.argv[0]} <filename>\n")

    print("--- Running 5 Test Cases ---")

    # Test Case 1: Valid and existing file
    print("\n--- Test Case 1: Valid File ---")
    valid_file = "test_valid.txt"
    try:
        with open(valid_file, "w", encoding='utf-8') as f:
            f.write("Hello Python!\nThis is a test file.")
        print(f"Result: \n{read_file_content(valid_file)}")
    except IOError as e:
        print(f"Test setup failed: {e}")
    finally:
        if os.path.exists(valid_file):
            os.remove(valid_file)

    # Test Case 2: Non-existent file
    print("\n--- Test Case 2: Non-existent File ---")
    print(f"Result: {read_file_content('nonexistent.txt')}")

    # Test Case 3: Filename is a directory
    print("\n--- Test Case 3: Path is a Directory ---")
    dir_name = "test_dir"
    try:
        if not os.path.exists(dir_name):
            os.mkdir(dir_name)
        print(f"Result: {read_file_content(dir_name)}")
    except OSError as e:
        print(f"Test setup failed: {e}")
    finally:
        if os.path.isdir(dir_name):
            os.rmdir(dir_name)

    # Test Case 4: None filename
    print("\n--- Test Case 4: None Filename ---")
    print(f"Result: {read_file_content(None)}")

    # Test Case 5: Empty/Whitespace filename
    print("\n--- Test Case 5: Empty/Whitespace Filename ---")
    print(f"Result: {read_file_content('  ')}")
    
    print("\n--- All tests completed ---")


if __name__ == "__main__":
    main()