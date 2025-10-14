import re
import os
from typing import List

def find_matching_lines(file_path: str) -> List[str]:
    """
    Reads a file and returns a list of lines that start with numbers and end with a dot.
    
    Args:
        file_path: The path to the file to read.
        
    Returns:
        A list of matching lines.
    """
    matching_lines = []
    # Regex: ^\d+.*\.$.
    # ^     - Start of the string
    # \d+   - One or more digits
    # .*    - Any character, zero or more times
    # \.    - A literal dot
    # $     - End of the string
    pattern = re.compile(r"^\d+.*\.$")
    
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return matching_lines

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Use rstrip() to remove trailing whitespace, including newline
                clean_line = line.rstrip()
                if pattern.fullmatch(clean_line):
                    matching_lines.append(clean_line)
    except IOError:
        # Return empty list if there's an error reading the file
        return []
    return matching_lines

def run_test_case(test_num: int, file_name: str, file_content: str):
    """Helper function to run a single test case."""
    print(f"--- Test Case {test_num} ---")
    try:
        # Create and write to the test file
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(file_content)

        # Run the function and print results
        print(f'File content:\n"""\n{file_content}"""')
        results = find_matching_lines(file_name)
        print(f"Matching lines found: {len(results)}")
        for line in results:
            print(f" > {line}")

    except IOError as e:
        print(f"An error occurred during test case {test_num}: {e}")
    finally:
        # Clean up the test file
        if os.path.exists(file_name):
            os.remove(file_name)
    print()

if __name__ == "__main__":
    file_name = "test_file_python.txt"

    # Test Case 1: Mixed content
    content1 = "123 this is a test.\n" \
               "456 another line that matches.\n" \
               "not a match\n" \
               "789 this line does not end with a dot\n" \
               "and another line that does not start with a number.\n" \
               "999.\n" \
               "1."
    run_test_case(1, file_name, content1)

    # Test Case 2: All lines match
    content2 = "1. First line.\n" \
               "20. Second line.\n" \
               "300. Third line."
    run_test_case(2, file_name, content2)

    # Test Case 3: No lines match
    content3 = "This starts with text.\n" \
               "123 this ends with no dot\n" \
               "Ends with a dot but no number."
    run_test_case(3, file_name, content3)

    # Test Case 4: Empty file
    content4 = ""
    run_test_case(4, file_name, content4)

    # Test Case 5: Lines with special regex characters
    content5 = "123.*.\n" \
               "456?[]\\d+.\n" \
               "abc."
    run_test_case(5, file_name, content5)