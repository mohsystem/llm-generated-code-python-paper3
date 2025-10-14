def parse_csv(csv_content):
    """
    Parses a CSV string into a list of lists of strings.
    This implementation handles quoted fields containing commas and escaped double quotes.

    :param csv_content: The string content of the CSV file.
    :return: A list of lists of strings representing the parsed CSV data.
    """
    if not csv_content:
        return []

    records = []
    lines = csv_content.strip().split('\n')
    
    for line in lines:
        if not line.strip():
            continue
        
        record = []
        current_field = ""
        in_quotes = False
        i = 0
        while i < len(line):
            char = line[i]
            
            if in_quotes:
                if char == '"':
                    # Check for escaped quote ("")
                    if i + 1 < len(line) and line[i+1] == '"':
                        current_field += '"'
                        i += 1 # Skip next quote
                    else:
                        in_quotes = False
                else:
                    current_field += char
            else:
                if char == '"':
                    in_quotes = True
                elif char == ',':
                    record.append(current_field)
                    current_field = ""
                else:
                    current_field += char
            i += 1
            
        record.append(current_field)
        records.append(record)
        
    return records

def main():
    test_cases = [
        # Test Case 1: Simple CSV
        "a,b,c\n1,2,3",
        # Test Case 2: Quoted fields with commas
        "\"a,b\",c\n1,\"2,3\"",
        # Test Case 3: Empty fields and empty quoted fields
        "a,,c\n1,\"\",3",
        # Test Case 4: Escaped quotes within a quoted field
        "a,\"b\"\"c\",d\n\"e \"\"f\"\"\",g",
        # Test Case 5: Mixed and complex cases
        "Name,Age,\"Address, City\"\nJohn Doe,30,\"123 Main St, \"\"Anytown\"\"\"\n\"Jane, Smith\",25,\"456 Oak Ave, Somewhere\""
    ]
    
    for i, test_case in enumerate(test_cases):
        print(f"--- Test Case {i + 1} ---")
        print(f"Input:\n{test_case}")
        result = parse_csv(test_case)
        print("Output:")
        for row in result:
            print(row)
        print()

if __name__ == "__main__":
    main()