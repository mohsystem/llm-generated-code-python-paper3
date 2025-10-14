import sys
import re
import os
import tempfile
from typing import List

def process_file(pattern_str: str, file_path: str):
    """
    Searches a file for lines matching a regular expression.

    Args:
        pattern_str: The regular expression to search for.
        file_path: The path to the file to search in.
    """
    if not os.path.isfile(file_path):
        print(f"Error: File not found or is not a regular file: {file_path}", file=sys.stderr)
        return

    try:
        pattern = re.compile(pattern_str)
    except re.error as e:
        print(f"Error: Invalid regular expression: {e}", file=sys.stderr)
        return

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if pattern.search(line):
                    print(line, end='')
    except (IOError, UnicodeDecodeError) as e:
        print(f"Error reading file {file_path}: {e}", file=sys.stderr)


def run_tests():
    """
    Runs a series of test cases using a temporary file.
    """
    print("Running built-in tests...")
    content = [
        "Hello World\n",
        "This is a test file.\n",
        "The quick brown fox jumps over the lazy dog.\n",
        "Contact us at test@example.com or support@example.org.\n",
        "Phone numbers: 123-456-7890, (987)654-3210.\n",
        "Another line with numbers 12345.\n",
        "end of file.\n"
    ]

    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=True, encoding='utf-8', suffix=".txt") as temp_f:
            temp_f.writelines(content)
            temp_f.seek(0) # Rewind to the beginning of the file for reading
            test_file_path = temp_f.name

            print("\n--- Test Case 1: Find lines with 'fox' ---")
            process_file("fox", test_file_path)

            print("\n--- Test Case 2: Find lines with any number ---")
            process_file(r"\d+", test_file_path)

            print("\n--- Test Case 3: Find lines with email addresses ---")
            process_file(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", test_file_path)

            print("\n--- Test Case 4: Find lines starting with 'The' ---")
            process_file(r"^The", test_file_path)

            print("\n--- Test Case 5: Find lines with 'nonexistentpattern' ---")
            process_file("nonexistentpattern", test_file_path)
            print("(No output expected)")

    except (IOError, OSError) as e:
        print(f"Failed to create or use temporary file for tests: {e}", file=sys.stderr)


def main():
    if len(sys.argv) == 3:
        process_file(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python your_script_name.py \"<regex_pattern>\" \"<file_name>\"")
        print("No command-line arguments provided, running test cases.")
        run_tests()

if __name__ == "__main__":
    main()