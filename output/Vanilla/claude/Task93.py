
def read_and_sort_file(filename):
    records = []
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    records.append(line)
    except IOError as e:
        print(f"Error reading file: {e}")
        return records
    
    records.sort()
    return records


def main():
    # Test case 1: Basic key-value pairs
    try:
        with open("test1.txt", "w") as f:
            f.write("name=John\\n")
            f.write("age=30\\n")
            f.write("city=Boston\\n")
        print("Test 1:")
        print(read_and_sort_file("test1.txt"))
    except IOError as e:
        print(e)
    
    # Test case 2: Numeric keys
    try:
        with open("test2.txt", "w") as f:
            f.write("3=apple\\n")
            f.write("1=banana\\n")
            f.write("2=cherry\\n")
        print("\\nTest 2:")
        print(read_and_sort_file("test2.txt"))
    except IOError as e:
        print(e)
    
    # Test case 3: Mixed case
    try:
        with open("test3.txt", "w") as f:
            f.write("Zebra=animal\\n")
            f.write("apple=fruit\\n")
            f.write("Banana=fruit\\n")
        print("\\nTest 3:")
        print(read_and_sort_file("test3.txt"))
    except IOError as e:
        print(e)
    
    # Test case 4: Empty lines
    try:
        with open("test4.txt", "w") as f:
            f.write("key1=value1\\n")
            f.write("\\n")
            f.write("key2=value2\\n")
            f.write("   \\n")
            f.write("key3=value3\\n")
        print("\\nTest 4:")
        print(read_and_sort_file("test4.txt"))
    except IOError as e:
        print(e)
    
    # Test case 5: Single record
    try:
        with open("test5.txt", "w") as f:
            f.write("onlykey=onlyvalue\\n")
        print("\\nTest 5:")
        print(read_and_sort_file("test5.txt"))
    except IOError as e:
        print(e)


if __name__ == "__main__":
    main()
