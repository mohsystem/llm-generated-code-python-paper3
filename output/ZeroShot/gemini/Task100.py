import sys
import re
import os

def search_file_with_regex(regex_pattern, file_path):
    """
    Searches a file for lines matching a given regular expression.
    
    Args:
        regex_pattern (str): The regular expression pattern to search for.
        file_path (str): The path to the file to be searched.
    """
    try:
        # Security: re.compile helps catch syntax errors early.
        # Python's re engine is relatively safe from catastrophic backtracking,
        # but very complex patterns on large inputs can still be slow.
        pattern = re.compile(regex_pattern)
    except re.error as e:
        print(f"Error: Invalid regular expression pattern: {e}", file=sys.stderr)
        return

    # Security: Check if path exists and is a file before opening.
    if not os.path.isfile(file_path):
        print(f"Error: File not found or is a directory: {file_path}", file=sys.stderr)
        return
    
    try:
        # Security: 'with open' ensures the file is closed automatically.
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if pattern.search(line):
                    # Strip newline for cleaner printing
                    print(f"{file_path}:{line_num}:{line.strip()}")
    except IOError as e:
        print(f"Error reading file '{file_path}': {e}", file=sys.stderr)

def run_tests():
    """Runs a series of test cases."""
    test_file_name = "test_file.txt"
    # Create a test file
    try:
        with open(test_file_name, 'w', encoding='utf-8') as f:
            f.write("Hello world, this is a test file.\n")
            f.write("The year is 2024.\n")
            f.write("Let's test some patterns.\n")
            f.write("Another line for testing.\n")
            f.write("bat, bit, but, b@t.\n")
            f.write("Goodbye!\n")
    except IOError as e:
        print(f"Failed to create test file: {e}", file=sys.stderr)
        return

    print("\n--- Test Case 1: Simple Match ('test') ---")
    search_file_with_regex("test", test_file_name)

    print("\n--- Test Case 2: No Match ('nomatch') ---")
    search_file_with_regex("nomatch", test_file_name)

    print("\n--- Test Case 3: Regex Special Chars ('b.t') ---")
    search_file_with_regex(r"b.t", test_file_name)

    print("\n--- Test Case 4: Digit Match ('\\d+') ---")
    search_file_with_regex(r"\d+", test_file_name)

    print("\n--- Test Case 5: Non-existent File ---")
    search_file_with_regex("hello", "nonexistent.txt")
    
    # Clean up the test file
    os.remove(test_file_name)


if __name__ == "__main__":
    if len(sys.argv) == 3:
        # Use command line arguments if provided
        search_file_with_regex(sys.argv[1], sys.argv[2])
    else:
        # Otherwise, run test cases
        print("Usage: python script.py <regex_pattern> <file_path>")
        print("Running test cases instead...")
        run_tests()