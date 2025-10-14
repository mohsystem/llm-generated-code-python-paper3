import os
from typing import List, Tuple

def sort_records_from_file(filepath: str) -> List[Tuple[str, str]]:
    """
    Reads key-value pairs from a file, sorts them by key, and returns them.

    Args:
        filepath: The path to the file. Must be a relative path without traversal.

    Returns:
        A sorted list of (key, value) tuples.

    Raises:
        ValueError: If the filepath is invalid (e.g., contains '..', is absolute).
        FileNotFoundError: If the file does not exist.
        IOError: For other file reading errors.
    """
    # Rule #7: Validate and sanitize all external input used in path construction.
    if not filepath or ".." in filepath or os.path.isabs(filepath):
        raise ValueError("Invalid file path: Only relative paths within the current directory are allowed.")

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    if not os.path.isfile(filepath):
         raise IOError(f"Path is not a regular file: {filepath}")

    records = []
    # Rule #8: Use 'with' statement for resource management.
    # Rule #9: Specify encoding.
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                trimmed_line = line.strip()
                if not trimmed_line or trimmed_line.startswith('#'):
                    continue

                # Rule #4: Validate that input conforms to the expected format.
                separator_index = trimmed_line.find(':')
                if separator_index <= 0 or separator_index == len(trimmed_line) - 1:
                    print(f"Warning: Malformed line {line_num}: {line.strip()}")
                    continue

                key = trimmed_line[:separator_index].strip()
                value = trimmed_line[separator_index + 1:].strip()

                if not key:
                    print(f"Warning: Malformed line (empty key) {line_num}: {line.strip()}")
                    continue

                records.append((key, value))
    except IOError as e:
        # Re-raise with a more specific context if needed
        raise IOError(f"Error reading file '{filepath}': {e}") from e

    # Sort records based on the key (the first element of the tuple)
    return sorted(records, key=lambda item: item[0])

def create_test_file(filename: str, content: str):
    """Helper function to create a test file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    except IOError as e:
        print(f"Failed to create test file {filename}: {e}")

def main():
    """Main function with test cases."""
    test_files = ["test1.txt", "test2.txt", "test3.txt"]
    
    # Test Case 1: Normal file
    create_test_file("test1.txt", "c:3\n a: 1 \n b:2\n")
    # Test Case 2: Empty file
    create_test_file("test2.txt", "")
    # Test Case 3: File with malformed lines
    create_test_file("test3.txt", "apple:red\n:empty_key\nbanana:\n# a comment\nmalformed line\norange: fruit\n")

    test_cases = [
        "test1.txt",
        "test2.txt",
        "test3.txt",
        "non_existent_file.txt",
        "../forbidden.txt"
    ]
    
    for i, test_path in enumerate(test_cases, 1):
        print(f"--- Test Case {i}: {test_path} ---")
        try:
            sorted_records = sort_records_from_file(test_path)
            if not sorted_records:
                print("No records found or file was empty/invalid.")
            else:
                for key, value in sorted_records:
                    print(f"{key}:{value}")
        except (ValueError, FileNotFoundError, IOError) as e:
            print(f"Error: {e}")
        print()

    # Cleanup
    for filename in test_files:
        if os.path.exists(filename):
            os.remove(filename)

if __name__ == "__main__":
    main()