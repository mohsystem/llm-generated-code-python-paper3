import os

def sort_file_records(file_path):
    """
    Reads a file containing key-value pairs, sorts them by key, and returns them.

    :param file_path: The path to the file.
    :return: A sorted list of (key, value) tuples, or None on error.
    """
    records = []
    try:
        # 'with' statement ensures the file is closed automatically.
        with open(file_path, 'r') as f:
            for line in f:
                # Split line at the first colon only.
                parts = line.strip().split(':', 1)
                if len(parts) == 2:
                    key, value = parts
                    key = key.strip()
                    if key:  # Ensure key is not an empty string
                        records.append((key, value.strip()))
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    # Sort the list of tuples based on the first element (the key).
    records.sort(key=lambda item: item[0])
    return records

# Main block with test cases
if __name__ == "__main__":
    
    def create_test_file(filename, content):
        try:
            with open(filename, 'w') as f:
                f.write(content)
        except Exception as e:
            print(f"Failed to create test file: {e}")

    def print_records(records):
        if records is None:
            print("Function returned None (likely an error occurred).")
            return
        if not records:
            print("No valid records found or processed.")
        else:
            for key, value in records:
                print(f"{key}: {value}")

    test_file_name = "test_records.txt"

    # Test Case 1: Standard case with unsorted records
    print("--- Test Case 1: Standard unsorted file ---")
    create_test_file(test_file_name, "banana: 10\napple: 5\ncherry: 20\ndate: 15")
    sorted_records_1 = sort_file_records(test_file_name)
    print_records(sorted_records_1)
    print()

    # Test Case 2: File with malformed lines, empty lines, and whitespace
    print("--- Test Case 2: File with malformed lines and whitespace ---")
    create_test_file(test_file_name, "  fig: 30  \n\ngrape: 25\njust_a_key\n:empty_key\nelderberry:")
    sorted_records_2 = sort_file_records(test_file_name)
    print_records(sorted_records_2)
    print()

    # Test Case 3: Empty file
    print("--- Test Case 3: Empty file ---")
    create_test_file(test_file_name, "")
    sorted_records_3 = sort_file_records(test_file_name)
    print_records(sorted_records_3)
    print()

    # Test Case 4: Non-existent file
    print("--- Test Case 4: Non-existent file ---")
    if os.path.exists(test_file_name):
        os.remove(test_file_name)
    sorted_records_4 = sort_file_records(test_file_name)
    print_records(sorted_records_4)
    print()

    # Test Case 5: Already sorted file
    print("--- Test Case 5: Already sorted file ---")
    create_test_file(test_file_name, "alpha: 1\nbeta: 2\ngamma: 3")
    sorted_records_5 = sort_file_records(test_file_name)
    print_records(sorted_records_5)
    print()

    # Cleanup the test file
    if os.path.exists(test_file_name):
        os.remove(test_file_name)