import os
from typing import List, Tuple

def read_file_records(filename: str) -> List[Tuple[str, str]]:
    """
    Reads key-value pairs from a file, with each line formatted as "key:value".
    Malformed lines are skipped.

    Args:
        filename: The path to the file to read.

    Returns:
        A list of (key, value) tuples.
    """
    records: List[Tuple[str, str]] = []
    try:
        # Use context manager for automatic file closing.
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                # Validate input format using partition for safety.
                key, sep, value = line.partition(':')
                if sep:
                    key = key.strip()
                    value = value.strip()
                    if key and value:
                        records.append((key, value))
                # Silently ignore malformed lines.
    except FileNotFoundError:
        print(f"Error: File not found at '{filename}'")
    except IOError as e:
        print(f"Error reading file '{filename}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return records

def sort_and_print_records(records: List[Tuple[str, str]]):
    """
    Sorts a list of key-value tuples by key and prints them.

    Args:
        records: The list of records to sort and print.
    """
    if not records:
        print("No records to display.")
        return

    # Sort records by key (default tuple sorting behavior).
    records.sort()

    # Print sorted records.
    for key, value in records:
        print(f"{key}: {value}")

def create_test_file(filename: str, content: str):
    """Helper function to create a test file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    except IOError as e:
        print(f"Failed to create test file '{filename}': {e}")
        raise

def main():
    """Main function with test cases."""
    test_cases = {
        "test1.txt": "c:3\na:1\nb:2",
        "test2.txt": "",
        "test3.txt": "z:26",
        "test4.txt": "b:1\na:2\nb:3",
        "test5.txt": "key1:value1\n:onlyvalue\nkeyonly:\nmalformed\nkey2:value2"
    }

    for i, (filename, content) in enumerate(test_cases.items()):
        print(f"----- Test Case {i + 1}: {filename} -----")
        try:
            # Setup
            create_test_file(filename, content)
            
            # Execute
            records = read_file_records(filename)
            
            # Process and Print
            sort_and_print_records(records)

        except Exception as e:
            print(f"An error occurred during test case {i + 1}: {e}")
        finally:
            # Teardown
            if os.path.exists(filename):
                try:
                    os.remove(filename)
                except OSError as e:
                    print(f"Error removing test file '{filename}': {e}")
        print()

if __name__ == "__main__":
    main()