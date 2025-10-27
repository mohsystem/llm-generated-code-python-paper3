import sys

def write_to_file(file_name, content):
    """
    Opens a file and writes the given content to it, overwriting existing content.
    Returns True on success, False on failure.
    """
    try:
        # 'w' mode opens the file for writing.
        # It creates the file if it does not exist, and truncates it if it exists.
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except IOError as e:
        print(f"An error occurred while writing to file: {e}", file=sys.stderr)
        return False

def verify_file_content(file_name, expected_content):
    """ Helper to verify content by reading the whole file. """
    try:
        with open(file_name, 'r', encoding='utf-8') as f:
            file_content = f.read()
        if file_content == expected_content:
            print(f"Verification SUCCESS for {file_name}")
        else:
            print(f"Verification FAILED for {file_name}")
            print(f"Expected: '{expected_content}'")
            print(f"Got: '{file_content}'")
    except IOError as e:
        print(f"An error occurred while reading file for verification: {e}", file=sys.stderr)

def main():
    # Test Case 1
    print("--- Test Case 1 ---")
    file1 = "important_config"
    content1 = "important_config"
    if write_to_file(file1, content1):
        print(f"Successfully wrote to {file1}")
        verify_file_content(file1, content1)
    print()

    # Test Case 2
    print("--- Test Case 2 ---")
    file2 = "test1.txt"
    content2 = "Hello World"
    if write_to_file(file2, content2):
        print(f"Successfully wrote to {file2}")
        verify_file_content(file2, content2)
    print()

    # Test Case 3
    print("--- Test Case 3 ---")
    file3 = "data.log"
    content3 = "Log entry: 2023-10-27"
    if write_to_file(file3, content3):
        print(f"Successfully wrote to {file3}")
        verify_file_content(file3, content3)
    print()

    # Test Case 4
    print("--- Test Case 4 ---")
    file4 = "empty_file.txt"
    content4 = ""
    if write_to_file(file4, content4):
        print(f"Successfully wrote to {file4}")
        verify_file_content(file4, content4)
    print()

    # Test Case 5
    print("--- Test Case 5 ---")
    file5 = "another_config.ini"
    content5 = "[settings]\nuser=admin"
    if write_to_file(file5, content5):
        print(f"Successfully wrote to {file5}")
        verify_file_content(file5, content5)
    print()

if __name__ == "__main__":
    main()