
def read_and_sort_file(filename):
    records = []
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if not line or '=' not in line:
                    continue
                
                parts = line.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    records.append((key, value))
    except IOError as e:
        print(f"Error reading file: {e}")
        return records
    
    # Sort by key
    records.sort(key=lambda x: x[0])
    
    return records


if __name__ == "__main__":
    # Test case 1
    print("Test Case 1:")
    with open("test1.txt", "w") as f:
        f.write("name=John\\n")
        f.write("age=30\\n")
        f.write("city=NewYork\\n")
    
    result1 = read_and_sort_file("test1.txt")
    for key, value in result1:
        print(f"{key}={value}")
    
    # Test case 2
    print("\\nTest Case 2:")
    with open("test2.txt", "w") as f:
        f.write("zebra=animal\\n")
        f.write("apple=fruit\\n")
        f.write("car=vehicle\\n")
    
    result2 = read_and_sort_file("test2.txt")
    for key, value in result2:
        print(f"{key}={value}")
    
    # Test case 3
    print("\\nTest Case 3:")
    with open("test3.txt", "w") as f:
        f.write("key3=value3\\n")
        f.write("key1=value1\\n")
        f.write("key2=value2\\n")
    
    result3 = read_and_sort_file("test3.txt")
    for key, value in result3:
        print(f"{key}={value}")
    
    # Test case 4 - Empty file
    print("\\nTest Case 4:")
    with open("test4.txt", "w") as f:
        pass
    
    result4 = read_and_sort_file("test4.txt")
    print(f"Records found: {len(result4)}")
    
    # Test case 5 - File with special characters
    print("\\nTest Case 5:")
    with open("test5.txt", "w") as f:
        f.write("user.name=admin\\n")
        f.write("server.port=8080\\n")
        f.write("app.version=1.0\\n")
    
    result5 = read_and_sort_file("test5.txt")
    for key, value in result5:
        print(f"{key}={value}")
