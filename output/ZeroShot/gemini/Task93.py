import os
from typing import List, Tuple

def read_and_sort_file(filepath: str) -> List[Tuple[str, str]]:
    """
    Reads a file with key-value pairs, sorts them by key, and returns a list of tuples.

    Args:
        filepath: The path to the input file.

    Returns:
        A list of (key, value) tuples, sorted by key.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If there is an error reading the file.
    """
    records = {}
    try:
        # 'with' statement ensures the file is closed automatically
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue  # Skip empty lines

                # Split on the first colon only to allow colons in the value
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    if key:  # Ensure key is not empty
                        records[key] = value
                # Malformed lines are ignored
    except FileNotFoundError:
        # Propagate exception for the caller to handle
        raise
    except IOError as e:
        # More general I/O errors
        raise IOError(f"Error reading file {filepath}: {e}")

    # Sort dictionary items by key (the first element of the tuple)
    return sorted(records.items())

def main():
    """Main function to run test cases."""
    test_contents = [
        # Test Case 1: Standard case with mixed order
        "banana:yellow\napple:red\norange:orange\ngrape:purple",
        # Test Case 2: Empty file
        "",
        # Test Case 3: File with malformed lines, empty lines, and extra whitespace
        "name: Alice\n\nage: 30\noccupation :Software Engineer\nlocation\n\ncity:New York",
        # Test Case 4: Case sensitivity test
        "Apple:fruit\napple:fruit\nZebra:animal\nzoo:place",
        # Test Case 5: Special characters in values and keys
        "url:http://example.com?a=1&b=2\n$pecial-key:value with spaces\nemail:test@example.com"
    ]

    for i, content in enumerate(test_contents, 1):
        test_filename = f"test_case_{i}.txt"
        print(f"--- Running Test Case {i} ---")
        
        try:
            # 1. Create and write to the test file
            with open(test_filename, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 2. Process the file
            sorted_records = read_and_sort_file(test_filename)
            
            # 3. Print the results
            if not sorted_records:
                print("No valid records found or file was empty.")
            else:
                for key, value in sorted_records:
                    print(f"{key}:{value}")

        except (FileNotFoundError, IOError) as e:
            print(f"An error occurred: {e}")
        finally:
            # 4. Clean up the test file
            if os.path.exists(test_filename):
                os.remove(test_filename)
        print()

if __name__ == "__main__":
    main()