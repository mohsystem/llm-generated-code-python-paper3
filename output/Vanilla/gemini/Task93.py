import os

def sort_file_records(file_path):
    """
    Reads a file with key-value pairs, sorts them by key,
    and returns a list of (key, value) tuples.
    """
    records = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if ':' in line:
                    parts = line.strip().split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        records.append((key, value))
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return []

    # Sort the list of tuples based on the first element (the key)
    records.sort(key=lambda item: item[0])
    return records

def main():
    """
    Main function to run test cases.
    """
    test_cases = {
        "test1.txt": "banana:fruit\napple:fruit\n carrot : vegetable ",
        "test2.txt": "zeta:26\nalpha:1\nbeta:2",
        "test3.txt": "",
        "test4.txt": "10:ten\n2:two\n1:one",
        "test5.txt": "apple:red\nApple:green\napple:yellow"
    }

    test_num = 1
    for filename, content in test_cases.items():
        print(f"--- Test Case {test_num} ({filename}) ---")
        try:
            # Create test file
            with open(filename, 'w') as f:
                f.write(content)
            
            # Process file
            sorted_records = sort_file_records(filename)
            
            # Print results
            if not sorted_records:
                print("No records found or file is empty.")
            else:
                for key, value in sorted_records:
                    print(f"{key}:{value}")
            
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            # Clean up
            if os.path.exists(filename):
                os.remove(filename)
        
        print()
        test_num += 1

if __name__ == "__main__":
    main()