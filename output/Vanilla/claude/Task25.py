
def number(lines):
    return [f"{i + 1}: {line}" for i, line in enumerate(lines)]

if __name__ == "__main__":
    # Test case 1: Empty list
    print(number([]))
    
    # Test case 2: Basic example
    print(number(["a", "b", "c"]))
    
    # Test case 3: Single element
    print(number(["hello"]))
    
    # Test case 4: Multiple words
    print(number(["hello world", "foo bar", "test"]))
    
    # Test case 5: Empty strings
    print(number(["", "a", ""]))
