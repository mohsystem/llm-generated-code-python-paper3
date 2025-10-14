
def transpose(filename):
    result = []
    try:
        with open(filename, 'r') as f:
            rows = [line.strip().split(' ') for line in f]
        
        if not rows:
            return result
        
        max_cols = max(len(row) for row in rows)
        
        for col in range(max_cols):
            transposed_row = []
            for row in rows:
                if col < len(row):
                    transposed_row.append(row[col])
            result.append(' '.join(transposed_row))
    except Exception as e:
        print(f"Error: {e}")
    
    return result

if __name__ == "__main__":
    # Test case 1
    with open("test1.txt", "w") as f:
        f.write("name age\\n")
        f.write("alice 21\\n")
        f.write("ryan 30\\n")
    print("Test 1:")
    for line in transpose("test1.txt"):
        print(line)
    print()
    
    # Test case 2
    with open("test2.txt", "w") as f:
        f.write("a b c\\n")
        f.write("d e f\\n")
        f.write("g h i\\n")
    print("Test 2:")
    for line in transpose("test2.txt"):
        print(line)
    print()
    
    # Test case 3
    with open("test3.txt", "w") as f:
        f.write("1 2\\n")
        f.write("3 4\\n")
    print("Test 3:")
    for line in transpose("test3.txt"):
        print(line)
    print()
    
    # Test case 4
    with open("test4.txt", "w") as f:
        f.write("x\\n")
        f.write("y\\n")
        f.write("z\\n")
    print("Test 4:")
    for line in transpose("test4.txt"):
        print(line)
    print()
    
    # Test case 5
    with open("test5.txt", "w") as f:
        f.write("first second third fourth\\n")
        f.write("1 2 3 4\\n")
    print("Test 5:")
    for line in transpose("test5.txt"):
        print(line)
    print()
