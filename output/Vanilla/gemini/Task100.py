import re
import sys
import os

def search_in_file(pattern, filename):
    """
    Searches for a regex pattern within a file and prints matching lines.
    """
    print(f"Searching for pattern '{pattern}' in file '{filename}'...")
    try:
        compiled_pattern = re.compile(pattern)
        with open(filename, 'r') as f:
            for line in f:
                if compiled_pattern.search(line):
                    print(f"Found match: {line.strip()}")
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.", file=sys.stderr)
    except re.error as e:
        print(f"Error: Invalid regular expression: {e}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    print("------------------------------------")


def run_test_cases():
    """
    Sets up test data and runs test cases.
    """
    test_filename = "test_file_python.txt"
    file_content = [
        "Hello world, this is a test file.",
        "The year is 2024.",
        "Contact us at test@example.com for more info.",
        "Or call 123-456-7890.",
        "This line contains no special characters or numbers",
        "Another email: another.email@domain.org."
    ]
    try:
        with open(test_filename, "w") as f:
            f.write("\n".join(file_content))
    except IOError as e:
        print(f"Failed to create test file: {e}", file=sys.stderr)
        return

    # Test Case 1: Match a 4-digit number
    search_in_file(r"\d{4}", test_filename)

    # Test Case 2: Match an email address
    search_in_file(r"\w+@\w+\.\w+", test_filename)

    # Test Case 3: Match a line starting with "Hello"
    search_in_file(r"^Hello", test_filename)

    # Test Case 4: Match a line ending with "numbers"
    search_in_file(r"numbers$", test_filename)

    # Test Case 5: A pattern that won't match anything
    search_in_file(r"NonExistentPatternXYZ", test_filename)

    # Cleanup the test file
    os.remove(test_filename)

if __name__ == "__main__":
    if len(sys.argv) == 3:
        # Use command-line arguments
        regex_pattern = sys.argv[1]
        file_name = sys.argv[2]
        search_in_file(regex_pattern, file_name)
    else:
        # Run built-in test cases
        print("Usage: python your_script_name.py <regex_pattern> <file_name>")
        print("Running test cases instead...\n")
        run_test_cases()