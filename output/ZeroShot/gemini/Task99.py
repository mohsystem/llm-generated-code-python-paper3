import re
import os

def find_matching_lines(file_path):
    """
    Reads a file and finds lines that start with a number and end with a dot.

    Args:
        file_path (str): The path to the file to read.

    Returns:
        list: A list of matching lines.
    """
    matching_lines = []
    # Regex: ^ (start of line), \d (a digit), .* (any characters), \. (literal dot), $ (end of line)
    # The pattern is simple and secure, with low risk of ReDoS.
    pattern = re.compile(r"^\d.*\.$")

    # Basic path validation to prevent obvious path traversal attacks.
    if ".." in file_path:
        print("Error: Invalid or insecure file path provided.")
        return matching_lines

    try:
        # 'with' statement ensures the file is closed securely
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # rstrip() removes trailing whitespace, including the newline character
                clean_line = line.rstrip()
                if pattern.match(clean_line):
                    matching_lines.append(clean_line)
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
    except IOError as e:
        print(f"Error reading file: {e}")
        
    return matching_lines

# Helper function to create a test file
def create_test_file(file_name, content):
    with open(file_name, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == "__main__":
    test_file_name = "test_python.txt"

    # --- Test Cases ---

    # Test Case 1: Standard case with mixed content
    print("--- Test Case 1: Standard File ---")
    content1 = ("1. This is a matching line.\n"
                "Not a match.\n"
                "2) Also not a match.\n"
                "3. Another match here.\n"
                "4 This line does not end with a dot\n"
                "This line does not start with a number.\n"
                "55. This one is also a match.")
    create_test_file(test_file_name, content1)
    matches1 = find_matching_lines(test_file_name)
    print(f"Found {len(matches1)} matches:")
    for m in matches1:
        print(m)
    print()

    # Test Case 2: Empty file
    print("--- Test Case 2: Empty File ---")
    create_test_file(test_file_name, "")
    matches2 = find_matching_lines(test_file_name)
    print(f"Found {len(matches2)} matches:")
    for m in matches2:
        print(m)
    print()

    # Test Case 3: File with no matching lines
    print("--- Test Case 3: No Matches ---")
    content3 = ("Hello world\n"
                "Another line without a dot\n"
                "Ends with a dot but no number.")
    create_test_file(test_file_name, content3)
    matches3 = find_matching_lines(test_file_name)
    print(f"Found {len(matches3)} matches:")
    for m in matches3:
        print(m)
    print()

    # Test Case 4: File where all lines match
    print("--- Test Case 4: All Lines Match ---")
    content4 = ("1. First line.\n"
                "2. Second line.\n"
                "3. Third line.")
    create_test_file(test_file_name, content4)
    matches4 = find_matching_lines(test_file_name)
    print(f"Found {len(matches4)} matches:")
    for m in matches4:
        print(m)
    print()

    # Test Case 5: Non-existent file
    print("--- Test Case 5: Non-existent File ---")
    matches5 = find_matching_lines("nonexistentfile.txt")
    print(f"Found {len(matches5)} matches.")

    # Cleanup the test file
    if os.path.exists(test_file_name):
        os.remove(test_file_name)