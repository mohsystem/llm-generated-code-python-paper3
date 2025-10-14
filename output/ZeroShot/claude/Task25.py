
def number(lines):
    if lines is None:
        return []
    
    result = []
    for i, line in enumerate(lines):
        result.append(f"{i + 1}: {line}")
    return result

if __name__ == "__main__":
    # Test case 1: Empty list
    print("Test 1:", number([]))
    
    # Test case 2: Simple list
    print("Test 2:", number(["a", "b", "c"]))
    
    # Test case 3: Single element
    print("Test 3:", number(["Hello World"]))
    
    # Test case 4: Multiple lines with different content
    print("Test 4:", number(["line one", "line two", "line three", "line four"]))
    
    # Test case 5: Lines with special characters
    print("Test 5:", number(["Hello!", "How are you?", "I'm fine, thanks."]))
