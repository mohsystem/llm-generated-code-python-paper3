
def parse_csv(csv_content):
    """\n    Parses CSV content and returns a list of lists.\n    """
    if not csv_content:
        return []
    
    records = []
    lines = csv_content.split('\\n')
    
    for line in lines:
        if line:
            record = parse_line(line)
            records.append(record)
    
    return records


def parse_line(line):
    """\n    Parses a single CSV line, handling quoted fields and escaped quotes.\n    """
    fields = []
    field = []
    in_quotes = False
    i = 0
    
    while i < len(line):
        c = line[i]
        
        if c == '"':
            if in_quotes and i + 1 < len(line) and line[i + 1] == '"':
                field.append('"')
                i += 1
            else:
                in_quotes = not in_quotes
        elif c == ',' and not in_quotes:
            fields.append(''.join(field))
            field = []
        else:
            field.append(c)
        
        i += 1
    
    fields.append(''.join(field))
    return fields


def print_csv(records):
    """\n    Prints CSV records.\n    """
    for record in records:
        print(record)


if __name__ == "__main__":
    # Test Case 1: Simple CSV
    csv1 = "Name,Age,City\\nJohn,30,New York\\nJane,25,Los Angeles"
    print("Test Case 1 - Simple CSV:")
    result1 = parse_csv(csv1)
    print_csv(result1)
    print()
    
    # Test Case 2: CSV with quoted fields
    csv2 = 'Name,Description\\n"John Doe","Software Engineer"\\n"Jane Smith","Data Scientist"'
    print("Test Case 2 - CSV with quoted fields:")
    result2 = parse_csv(csv2)
    print_csv(result2)
    print()
    
    # Test Case 3: CSV with commas in quoted fields
    csv3 = 'Product,Price,Description\\nLaptop,1200,"High performance, 16GB RAM"\\nPhone,800,"5G enabled, dual camera"'
    print("Test Case 3 - CSV with commas in quoted fields:")
    result3 = parse_csv(csv3)
    print_csv(result3)
    print()
    
    # Test Case 4: CSV with escaped quotes
    csv4 = 'Title,Quote\\nBook,"He said ""Hello"""\\nMovie,"She said ""Goodbye"""'
    print("Test Case 4 - CSV with escaped quotes:")
    result4 = parse_csv(csv4)
    print_csv(result4)
    print()
    
    # Test Case 5: Empty and single line CSV
    csv5 = "Header1,Header2,Header3"
    print("Test Case 5 - Single line CSV:")
    result5 = parse_csv(csv5)
    print_csv(result5)
