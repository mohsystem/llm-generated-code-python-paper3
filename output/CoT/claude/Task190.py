
def transpose(filename):
    result = []
    matrix = []
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(' ')
                matrix.append(parts)
        
        if not matrix:
            return result
        
        cols = len(matrix[0])
        for j in range(cols):
            row = []
            for i in range(len(matrix)):
                if j < len(matrix[i]):
                    row.append(matrix[i][j])
            result.append(' '.join(row))
    
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
    except IOError as e:
        print(f"Error reading file: {e}")
    
    return result

if __name__ == "__main__":
    # Test case 1: Basic example
    try:
        with open("test1.txt", "w") as f:
            f.write("name age\\n")
            f.write("alice 21\\n")
            f.write("ryan 30\\n")
        print("Test 1:")
        for line in transpose("test1.txt"):
            print(line)
        print()
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 2: Single row
    try:
        with open("test2.txt", "w") as f:
            f.write("a b c d\\n")
        print("Test 2:")
        for line in transpose("test2.txt"):
            print(line)
        print()
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 3: Single column
    try:
        with open("test3.txt", "w") as f:
            f.write("a\\n")
            f.write("b\\n")
            f.write("c\\n")
        print("Test 3:")
        for line in transpose("test3.txt"):
            print(line)
        print()
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 4: 3x3 matrix
    try:
        with open("test4.txt", "w") as f:
            f.write("1 2 3\\n")
            f.write("4 5 6\\n")
            f.write("7 8 9\\n")
        print("Test 4:")
        for line in transpose("test4.txt"):
            print(line)
        print()
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 5: Empty file
    try:
        with open("test5.txt", "w") as f:
            pass
        print("Test 5:")
        result = transpose("test5.txt")
        if not result:
            print("Empty result")
        print()
    except Exception as e:
        print(f"Error: {e}")
