import sys

def parse_csv(csv_data: str):
    """
    Parses a string in CSV format into a list of lists of strings.
    This is a simple parser and does not handle quoted fields.

    :param csv_data: The string containing CSV data.
    :return: A list of lists, where each inner list represents a row.
    """
    if not csv_data:
        return []
    
    # splitlines() handles various newline characters
    lines = csv_data.strip().splitlines()
    records = [line.split(',') for line in lines]
    return records

def main():
    """ Main function with test cases """
    test_cases = [
        # Test Case 1: Standard CSV
        "a,b,c\n1,2,3\nx,y,z",
        # Test Case 2: Empty fields and trailing commas
        "a,,c\n1,2,\n,y,z",
        # Test Case 3: Single row
        "one,two,three,four",
        # Test Case 4: Single column
        "one\ntwo\nthree",
        # Test Case 5: Empty input
        ""
    ]

    for i, test_str in enumerate(test_cases):
        print(f"--- Test Case {i + 1} ---")
        print(f"Input:\n\"{test_str}\"")
        parsed_data = parse_csv(test_str)
        print("Output:")
        print(parsed_data)
        print()

if __name__ == "__main__":
    main()