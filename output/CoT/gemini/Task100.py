import sys
import re
import os

def search_file_with_regex(regex_pattern, file_name):
    """
    Searches a file for lines matching a given regular expression.

    Args:
        regex_pattern (str): The regular expression pattern to search for.
        file_name (str): The path to the file to be searched.
    """
    # Step 1: Compile the regular expression
    try:
        pattern = re.compile(regex_pattern)
    except re.error as e:
        print(f"Error: Invalid regular expression pattern: {e}", file=sys.stderr)
        return

    # Check for file existence and readability before opening
    if not os.path.exists(file_name):
        print(f"Error: File not found: {file_name}", file=sys.stderr)
        return
    if not os.access(file_name, os.R_OK):
        print(f"Error: Cannot read file (permission denied): {file_name}", file=sys.stderr)
        return

    # Step 2: Read the file and search for the pattern line by line
    try:
        # Use 'with' statement for automatic file closing
        with open(file_name, 'r', encoding='utf-8') as f:
            found = False
            for line_num, line in enumerate(f, 1):
                # rstrip() to remove trailing newline character
                if pattern.search(line):
                    print(f"Match found on line {line_num}: {line.rstrip()}")
                    found = True
            if not found:
                print(f"No matches found for pattern '{regex_pattern}' in file '{file_name}'.")

    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)


def run_tests():
    """Creates a temporary file and runs a series of test cases."""
    test_file_name = "test_file.txt"
    file_content = [
        "Hello world, this is a test file.",
        "The quick brown fox jumps over the lazy dog.",
        "123-456-7890 is a phone number.",
        "Another line with the word world.",
        "Email: test@example.com",
        "invalid-email@.com"
    ]
    try:
        with open(test_file_name, 'w', encoding='utf-8') as f:
            f.write('\n'.join(file_content))
    except IOError as e:
        print(f"Failed to create test file: {e}", file=sys.stderr)
        return

    test_cases = [
        ("world", "Test Case 1: Simple word match"),
        ("^[A-Z]", "Test Case 2: Match lines starting with a capital letter"),
        (r"\d{3}-\d{3}-\d{4}", "Test Case 3: Match a phone number format"),
        ("fox|dog", "Test Case 4: Match using alternation"),
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Test Case 5: Match a valid email address")
    ]
    
    for pattern, description in test_cases:
        print(f"\n--- {description} ---")
        print(f"Pattern: {pattern}")
        print("------------------------------------")
        search_file_with_regex(pattern, test_file_name)

    # Clean up the test file
    os.remove(test_file_name)


if __name__ == "__main__":
    # Check if command line arguments are provided
    if len(sys.argv) == 3:
        print("--- Running with Command Line Arguments ---")
        regex = sys.argv[1]
        file_path = sys.argv[2]
        print(f"Pattern: {regex}")
        print(f"File: {file_path}")
        print("-------------------------------------------")
        search_file_with_regex(regex, file_path)
    else:
        print("Usage: python <script_name>.py <regex_pattern> <file_name>")
        print("Running built-in test cases as no arguments were provided.")
        run_tests()