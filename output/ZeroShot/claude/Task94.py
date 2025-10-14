
def read_and_sort_file(filename):
    records = []
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if line and '=' in line:
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        records.append((parts[0].strip(), parts[1].strip()))
    except IOError as e:
        print(f"Error reading file: {e}")
        return []
    
    # Sort by key
    records.sort(key=lambda x: x[0])
    return records


def create_test_file(filename, lines):
    try:
        with open(filename, 'w') as file:
            for line in lines:
                file.write(line + '\\n')
    except IOError as e:
        print(f"Error creating test file: {e}")


def print_records(records):
    for key, value in records:
        print(f"{key} = {value}")


if __name__ == "__main__":
    # Test case 1: Basic key-value pairs
    create_test_file("test1.txt", ["name=John", "age=30", "city=NewYork"])
    print("Test 1:")
    print_records(read_and_sort_file("test1.txt"))
    
    # Test case 2: Unsorted keys
    create_test_file("test2.txt", ["zebra=animal", "apple=fruit", "car=vehicle"])
    print("\\nTest 2:")
    print_records(read_and_sort_file("test2.txt"))
    
    # Test case 3: Keys with spaces
    create_test_file("test3.txt", ["first name=Alice", "last name=Smith", "age=25"])
    print("\\nTest 3:")
    print_records(read_and_sort_file("test3.txt"))
    
    # Test case 4: Duplicate keys
    create_test_file("test4.txt", ["color=red", "color=blue", "shape=circle"])
    print("\\nTest 4:")
    print_records(read_and_sort_file("test4.txt"))
    
    # Test case 5: Empty and invalid lines
    create_test_file("test5.txt", ["valid=data", "", "invalid_line", "another=valid"])
    print("\\nTest 5:")
    print_records(read_and_sort_file("test5.txt"))
