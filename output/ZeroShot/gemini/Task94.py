import os
from typing import List, Tuple

def sort_file_records(file_path: str) -> List[Tuple[str, str]]:
    """
    Reads a file with key-value pairs, sorts them by key, and returns a list of tuples.
    
    Args:
        file_path: The path to the file. Caller should ensure the path is safe.
        
    Returns:
        A list of (key, value) tuples sorted by key. Returns an empty list on error.
    """
    records = {}
    try:
        # 'with' statement ensures the file is closed automatically and safely.
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue  # Skip empty or whitespace-only lines

                # partition is safer than split as it doesn't raise an error
                # if the separator is not found. It splits on the first occurrence.
                key, sep, value = line.partition(':')
                
                if sep:  # The separator was found
                    key = key.strip()
                    value = value.strip()
                    if key: # Ensure key is not empty
                        records[key] = value
                else:
                    print(f"Warning: Skipping malformed line: {line}")
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
        return []
    except IOError as e:
        print(f"Error reading file '{file_path}': {e}")
        return []

    # Sort the dictionary items by key (the first element of the tuple)
    return sorted(records.items())

def setup_test_files():
    """Creates files needed for testing."""
    try:
        with open("test_ok.txt", "w") as f:
            f.write("zulu:last\nalpha:first\ncharlie:third\nbravo:second\n")
        
        with open("test_malformed.txt", "w") as f:
            f.write("key1:value1\nmalformedline\nkey2:value2\nanother:malformed:line\n")

        with open("test_empty.txt", "w") as f:
            pass # Create empty file

        with open("test_blank_lines.txt", "w") as f:
            f.write("keyA:valueA\n\n  \nkeyC:valueC\nkeyB:valueB\n")
    except IOError as e:
        print(f"Failed to set up test files: {e}")

def cleanup_test_files():
    """Removes files created for testing."""
    files = ["test_ok.txt", "test_malformed.txt", "test_empty.txt", "test_blank_lines.txt"]
    for f in files:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError as e:
                print(f"Failed to delete test file {f}: {e}")

def main():
    """Main function with test cases."""
    setup_test_files()
    
    test_files = [
        "test_ok.txt",
        "test_malformed.txt",
        "test_empty.txt",
        "test_blank_lines.txt",
        "non_existent_file.txt"
    ]
    
    for i, file in enumerate(test_files, 1):
        print(f"--- Test Case {i}: Processing {file} ---")
        result = sort_file_records(file)
        if not result:
            print("Result is empty (as expected for empty, malformed, or non-existent files).")
        else:
            for key, value in result:
                print(f"{key}:{value}")
        print()
        
    cleanup_test_files()

if __name__ == "__main__":
    main()