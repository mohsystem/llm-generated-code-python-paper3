import sys
import os

def read_file_content(filename):
    """
    Reads the content of a file after validating the filename.
    
    Args:
        filename (str): The name of the file to read.
    
    Returns:
        str: The content of the file, or None if an error occurs.
    """
    if not filename:
        print("Error: Filename cannot be empty.", file=sys.stderr)
        return None

    # Security: Prevent path traversal attacks.
    if ".." in filename:
        print("Error: Invalid filename. Path traversal is not allowed.", file=sys.stderr)
        return None

    try:
        # Security: Normalize the path to resolve any symbolic links or redundant separators.
        # This helps in ensuring checks are performed on the canonical path.
        normalized_path = os.path.normpath(os.path.abspath(filename))
        
        # Basic validation
        if not os.path.exists(normalized_path):
            print(f"Error: File does not exist: {normalized_path}", file=sys.stderr)
            return None
        if not os.path.isfile(normalized_path):
            print(f"Error: Path is not a regular file: {normalized_path}", file=sys.stderr)
            return None
        if not os.access(normalized_path, os.R_OK):
            print(f"Error: File is not readable (permission denied): {normalized_path}", file=sys.stderr)
            return None

        with open(normalized_path, 'r', encoding='utf-8') as f:
            return f.read()

    except (IOError, OSError, PermissionError) as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None

def run_tests():
    """Helper function to run test cases"""
    print("--- Running Tests ---")

    # Test Case 1: Valid file with content
    print("\n--- Test Case 1: Read a valid file ---")
    test_file_1 = "test1.txt"
    content_1 = "Hello World!"
    with open(test_file_1, "w") as f:
        f.write(content_1)
    result_1 = read_file_content(test_file_1)
    print(f"Expected: {content_1}")
    print(f"Got: {result_1}")
    print(f"Test {'PASSED' if content_1 == result_1 else 'FAILED'}")

    # Test Case 2: Empty file
    print("\n--- Test Case 2: Read an empty file ---")
    test_file_2 = "test2.txt"
    with open(test_file_2, "w") as f:
        pass
    result_2 = read_file_content(test_file_2)
    print("Expected: ")
    print(f"Got: {result_2}")
    print(f"Test {'PASSED' if '' == result_2 else 'FAILED'}")

    # Test Case 3: Non-existent file
    print("\n--- Test Case 3: Read a non-existent file ---")
    result_3 = read_file_content("nonexistent.txt")
    print("Expected: None (with error message)")
    print(f"Got: {result_3}")
    print(f"Test {'PASSED' if result_3 is None else 'FAILED'}")

    # Test Case 4: Path traversal attempt
    print("\n--- Test Case 4: Path traversal attempt ---")
    result_4 = read_file_content("../somefile.txt")
    print("Expected: None (with error message)")
    print(f"Got: {result_4}")
    print(f"Test {'PASSED' if result_4 is None else 'FAILED'}")

    # Test Case 5: File with multi-line content
    print("\n--- Test Case 5: Read a multi-line file ---")
    test_file_5 = "test5.txt"
    content_5 = "Line 1\nLine 2\nLine 3"
    with open(test_file_5, "w") as f:
        f.write(content_5)
    result_5 = read_file_content(test_file_5)
    print(f"Expected:\n{content_5}")
    print(f"Got:\n{result_5}")
    print(f"Test {'PASSED' if content_5 == result_5 else 'FAILED'}")
    
    # Cleanup
    if os.path.exists(test_file_1):
        os.remove(test_file_1)
    if os.path.exists(test_file_2):
        os.remove(test_file_2)
    if os.path.exists(test_file_5):
        os.remove(test_file_5)
        
    print("\n--- Tests Finished ---")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        print(f"Attempting to read file from command line: {filename}")
        content = read_file_content(filename)
        if content is not None:
            print("\n--- File Content ---")
            print(content)
            print("--- End of Content ---")
        else:
            print("Failed to read file.")
    else:
        print("No filename provided via command line. Running built-in test cases.")
        run_tests()