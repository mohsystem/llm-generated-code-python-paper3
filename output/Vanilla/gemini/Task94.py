import os

def sort_file_records(filename):
    """
    Reads a file with key:value records, sorts them by key, and returns a list of tuples.
    """
    records = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    # Split only on the first colon
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        records.append((parts[0].strip(), parts[1].strip()))
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []

    # Python's sort on a list of tuples sorts by the first element by default
    records.sort()
    return records

def main():
    test_contents = [
        # Test 1: Standard case
        "banana:fruit\napple:fruit\ncarrot:vegetable",
        # Test 2: Already sorted
        "alpha:1\nbeta:2\ngamma:3",
        # Test 3: Reverse sorted
        "zulu:end\nyankee:middle\nxray:start",
        # Test 4: Empty file
        "",
        # Test 5: Single entry
        "one:1"
    ]

    for i, content in enumerate(test_contents):
        test_filename = f"test_file_python_{i}.txt"
        try:
            # Create a temporary file for the test case
            with open(test_filename, 'w') as f:
                f.write(content)

            print(f"--- Test Case {i + 1} (Python) ---")
            print(f"Input from {test_filename}:")
            print(content if content else "<empty>")

            sorted_records = sort_file_records(test_filename)

            print("\nSorted Output:")
            if sorted_records:
                for key, value in sorted_records:
                    print(f"{key}:{value}")
            else:
                print("<no records to sort>")
            print()

        finally:
            # Clean up the temporary file
            if os.path.exists(test_filename):
                os.remove(test_filename)

if __name__ == "__main__":
    main()