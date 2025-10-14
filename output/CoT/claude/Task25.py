
def number(lines):
    if lines is None:
        return []
    
    result = []
    for i, line in enumerate(lines):
        if line is None:
            line = ""
        result.append(f"{i + 1}: {line}")
    return result

if __name__ == "__main__":
    # Test case 1: Empty list
    print("Test 1:", number([]))
    
    # Test case 2: Basic example
    print("Test 2:", number(["a", "b", "c"]))
    
    # Test case 3: Single element
    print("Test 3:", number(["hello"]))
    
    # Test case 4: Strings with special characters
    print("Test 4:", number(["Hello, World!", "Line with spaces", "Special @#$%"]))
    
    # Test case 5: Empty strings
    print("Test 5:", number(["", "non-empty", ""]))
