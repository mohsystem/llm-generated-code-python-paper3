import os

def sort_key_value_file(file_path):
    """
    Reads a file containing key-value pairs separated by a colon,
    sorts them by key, and prints the result.

    :param file_path: The path to the input file.
    """
    records = {}
    try:
        # The 'with' statement ensures the file is closed automatically.
        with open(file_path, 'r') as f:
            for line in f:
                # Split the line only on the first occurrence of the delimiter.
                parts = line.strip().split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    if key:  # Ensure the key is not empty
                        records[key] = value

        # Sort keys alphabetically and print the corresponding records.
        for key in sorted(records.keys()):
            print(f"{key}: {records[key]}")

    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
    except IOError as e:
        print(f"Error processing file {file_path}: {e}")

def create_test_file(file_name, content):
    """Helper function to create a test file."""
    try:
        with open(file_name, 'w') as f:
            f.write(content)
    except IOError as e:
        print(f"Failed to create test file {file_name}: {e}")

def main():
    """Main function with test cases."""
    # --- Test Cases ---

    # Test Case 1: Normal file with unsorted data
    print("--- Test Case 1: Normal File ---")
    test_file1 = "test1.txt"
    create_test_file(test_file1, "banana:fruit\napple:fruit\ncarrot:vegetable\nzucchini:vegetable\n")
    sort_key_value_file(test_file1)
    print()

    # Test Case 2: Empty file
    print("--- Test Case 2: Empty File ---")
    test_file2 = "test2.txt"
    create_test_file(test_file2, "")
    sort_key_value_file(test_file2)
    print()

    # Test Case 3: File with malformed lines
    print("--- Test Case 3: Malformed Lines ---")
    test_file3 = "test3.txt"
    create_test_file(test_file3, "one:1\ntwo_malformed\nthree:3\n:missing_key\nfour::4\n")
    sort_key_value_file(test_file3)
    print()

    # Test Case 4: Non-existent file
    print("--- Test Case 4: Non-existent File ---")
    test_file4 = "non_existent_file.txt"
    sort_key_value_file(test_file4)
    print()

    # Test Case 5: File with duplicate keys (last one should win)
    print("--- Test Case 5: Duplicate Keys ---")
    test_file5 = "test5.txt"
    create_test_file(test_file5, "key1:valueA\nkey2:valueB\nkey1:valueC\n")
    sort_key_value_file(test_file5)
    print()
    
    # Cleanup test files
    for f in [test_file1, test_file2, test_file3, test_file5]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    main()