
def transpose_file(filename):
    result = []
    rows = []
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                columns = line.strip().split(' ')
                rows.append(columns)
        
        if not rows:
            return result
        
        num_cols = len(rows[0])
        for col in range(num_cols):
            transposed_row = []
            for row in range(len(rows)):
                transposed_row.append(rows[row][col])
            result.append(' '.join(transposed_row))
    
    except IOError as e:
        print(f"Error reading file: {e}")
    
    return result


if __name__ == "__main__":
    # Test case 1: Basic example
    with open("test1.txt", "w") as f:
        f.write("name age\\n")
        f.write("alice 21\\n")
        f.write("ryan 30\\n")
    
    print("Test 1:")
    result = transpose_file("test1.txt")
    for line in result:
        print(line)
    print()
    
    # Test case 2: Single row
    with open("test2.txt", "w") as f:
        f.write("a b c d\\n")
    
    print("Test 2:")
    result = transpose_file("test2.txt")
    for line in result:
        print(line)
    print()
    
    # Test case 3: Single column
    with open("test3.txt", "w") as f:
        f.write("a\\n")
        f.write("b\\n")
        f.write("c\\n")
    
    print("Test 3:")
    result = transpose_file("test3.txt")
    for line in result:
        print(line)
    print()
    
    # Test case 4: 3x3 matrix
    with open("test4.txt", "w") as f:
        f.write("1 2 3\\n")
        f.write("4 5 6\\n")
        f.write("7 8 9\\n")
    
    print("Test 4:")
    result = transpose_file("test4.txt")
    for line in result:
        print(line)
    print()
    
    # Test case 5: Multiple columns
    with open("test5.txt", "w") as f:
        f.write("first last age city\\n")
        f.write("john doe 25 NYC\\n")
        f.write("jane smith 30 LA\\n")
    
    print("Test 5:")
    result = transpose_file("test5.txt")
    for line in result:
        print(line)
    print()
