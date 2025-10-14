
def parse_csv(csv_content):
    records = []
    if not csv_content:
        return records
    
    lines = csv_content.split('\\n')
    for line in lines:
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
        records.append(fields)
    
    return records


def print_csv(records):
    for record in records:
        print(record)


if __name__ == "__main__":
    # Test case 1: Simple CSV
    print("Test Case 1: Simple CSV")
    csv1 = "Name,Age,City\\nJohn,30,New York\\nAlice,25,London"
    result1 = parse_csv(csv1)
    print_csv(result1)
    print()
    
    # Test case 2: CSV with quoted fields
    print("Test Case 2: CSV with quoted fields")
    csv2 = "Name,Description\\nProduct A,\"This is a product\"\\nProduct B,\"Another product\""
    result2 = parse_csv(csv2)
    print_csv(result2)
    print()
    
    # Test case 3: CSV with commas in quoted fields
    print("Test Case 3: CSV with commas in quoted fields")
    csv3 = "Name,Address\\nJohn,\"123 Main St, Apt 4\"\\nAlice,\"456 Oak Ave, Suite 10\""
    result3 = parse_csv(csv3)
    print_csv(result3)
    print()
    
    # Test case 4: CSV with escaped quotes
    print("Test Case 4: CSV with escaped quotes")
    csv4 = "Title,Quote\\nBook,\"He said \"\"Hello\"\"\"\\nMovie,\"She replied \"\"Hi\"\"\""
    result4 = parse_csv(csv4)
    print_csv(result4)
    print()
    
    # Test case 5: Empty and mixed content
    print("Test Case 5: Empty and mixed content")
    csv5 = "A,B,C\\n1,,3\\n,5,\\n7,8,9"
    result5 = parse_csv(csv5)
    print_csv(result5)
