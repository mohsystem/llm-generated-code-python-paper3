
def read_and_sort_file(filename):
    records = []
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    records.append(line)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return records
    except Exception as e:
        print(f"Error reading file: {e}")
        return records
    
    records.sort()
    return records


if __name__ == "__main__":
    # Test case 1: File with simple key-value pairs
    with open("test1.txt", "w") as f:
        f.write("name=John\\n")
        f.write("age=30\\n")
        f.write("city=New York\\n")
    
    print("Test 1:")
    result1 = read_and_sort_file("test1.txt")
    for record in result1:
        print(record)
    print()
    
    # Test case 2: File with numeric keys
    with open("test2.txt", "w") as f:
        f.write("3=three\\n")
        f.write("1=one\\n")
        f.write("2=two\\n")
    
    print("Test 2:")
    result2 = read_and_sort_file("test2.txt")
    for record in result2:
        print(record)
    print()
    
    # Test case 3: File with mixed keys
    with open("test3.txt", "w") as f:
        f.write("zebra=animal\\n")
        f.write("apple=fruit\\n")
        f.write("car=vehicle\\n")
        f.write("banana=fruit\\n")
    
    print("Test 3:")
    result3 = read_and_sort_file("test3.txt")
    for record in result3:
        print(record)
    print()
    
    # Test case 4: Empty file
    with open("test4.txt", "w") as f:
        pass
    
    print("Test 4 (empty file):")
    result4 = read_and_sort_file("test4.txt")
    print(f"Records count: {len(result4)}")
    print()
    
    # Test case 5: File with duplicate keys
    with open("test5.txt", "w") as f:
        f.write("key1=value1\\n")
        f.write("key3=value3\\n")
        f.write("key1=value2\\n")
        f.write("key2=value4\\n")
    
    print("Test 5:")
    result5 = read_and_sort_file("test5.txt")
    for record in result5:
        print(record)
    print()
