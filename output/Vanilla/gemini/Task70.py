import sys
import os

def read_file_content(file_path):
    """
    Reads the entire content of a file into a string.

    :param file_path: The path to the file.
    :return: The content of the file as a string, or an error message if the file cannot be read.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error: Could not read file '{file_path}'. Reason: {e}"

def create_test_file(file_name, content):
    """Helper function to create a test file."""
    with open(file_name, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    """Main function to handle command-line args or run tests."""
    # Handle command-line argument if provided
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"Reading content from command line argument: {file_path}")
        print("--- File Content ---")
        print(read_file_content(file_path))
        print("--- End of Content ---")
        return # Exit after processing command line arg

    # Run built-in test cases if no command-line argument is provided
    print("No command line argument provided. Running built-in test cases...")
    print("=========================================================")

    # Test Case 1: Simple file
    print("Test Case 1: Reading a simple file (test1.txt)")
    try:
        file_name1 = "test1.txt"
        create_test_file(file_name1, "Hello World from Python!")
        print(f"Content: {read_file_content(file_name1)}")
        os.remove(file_name1)
    except Exception as e:
        print(f"Test Case 1 failed to set up: {e}")
    print("---------------------------------------------------------")

    # Test Case 2: File with multiple lines
    print("Test Case 2: Reading a multi-line file (test2.txt)")
    try:
        file_name2 = "test2.txt"
        create_test_file(file_name2, "Line 1\nLine 2\nLine 3")
        print(f"Content:\n{read_file_content(file_name2)}")
        os.remove(file_name2)
    except Exception as e:
        print(f"Test Case 2 failed to set up: {e}")
    print("---------------------------------------------------------")

    # Test Case 3: Empty file
    print("Test Case 3: Reading an empty file (test3.txt)")
    try:
        file_name3 = "test3.txt"
        create_test_file(file_name3, "")
        print(f"Content: '{read_file_content(file_name3)}'")
        os.remove(file_name3)
    except Exception as e:
        print(f"Test Case 3 failed to set up: {e}")
    print("---------------------------------------------------------")

    # Test Case 4: Non-existent file
    print("Test Case 4: Attempting to read a non-existent file")
    non_existent_file = "nonexistentfile.txt"
    print(f"Content: {read_file_content(non_existent_file)}")
    print("---------------------------------------------------------")

    # Test Case 5: File with special characters
    print("Test Case 5: Reading a file with special characters (test5.txt)")
    try:
        file_name5 = "test5.txt"
        create_test_file(file_name5, "UTF-8 test: áéíóú ñ €")
        print(f"Content: {read_file_content(file_name5)}")
        os.remove(file_name5)
    except Exception as e:
        print(f"Test Case 5 failed to set up: {e}")
    print("=========================================================")

if __name__ == '__main__':
    main()