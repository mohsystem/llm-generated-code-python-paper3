import csv
import io

def parse_csv(csv_content: str):
    """
    Securely parses a CSV string using Python's built-in csv module.
    The csv module is robust and handles various edge cases like quoted fields,
    escaped quotes, and newlines within fields. Using a standard, well-tested
    library is a key secure coding practice.
    
    Args:
        csv_content: The string content of the CSV file.
    
    Returns:
        A list of lists of strings representing the CSV data.
    """
    if not isinstance(csv_content, str) or not csv_content.strip():
        return []
        
    # Use io.StringIO to treat the string as a file
    # This avoids insecure file system operations and path traversal vulnerabilities
    file_like_object = io.StringIO(csv_content)
    
    # Use the csv reader to parse the content
    # It correctly handles quotes, commas in fields, and other CSV nuances.
    try:
        reader = csv.reader(file_like_object)
        return [row for row in reader]
    except csv.Error as e:
        # Handle potential parsing errors gracefully
        print(f"Error parsing CSV content: {e}")
        return []

def main():
    """ Main function with test cases """
    test_cases = [
        # Test Case 1: Simple CSV
        "a,b,c\n1,2,3",
        
        # Test Case 2: Quoted fields with commas
        "a,\"b,c\",d\n1,\"hello, world\",3",
        
        # Test Case 3: Escaped quotes inside quoted fields
        "a,\"b\"\"c\",d\n1,\"it's \"\"ok\"\"\",3",
        
        # Test Case 4: Malformed/edge cases (inconsistent columns, empty lines)
        "a,b\n1,2,3\n\n,d",
        
        # Test Case 5: Complex case with mixed quoting and commas
        "Name,Address,Notes\n\"Doe, John\",\"120 Main St, \"\"Anytown\"\"\",\"He said, \"\"Hello!\"\"\""
    ]

    for i, test_str in enumerate(test_cases):
        print(f"--- Test Case {i+1} ---")
        print(f"Input:\n{test_str}")
        result = parse_csv(test_str)
        print("Output:")
        for j, row in enumerate(result):
            print(f"Row {j}: {row}")
        print()

if __name__ == "__main__":
    main()