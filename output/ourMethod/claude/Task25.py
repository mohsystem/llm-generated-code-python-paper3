
from typing import List

def number(lines: List[str]) -> List[str]:
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
    print(number([]))
    
    # Test case 2: Basic example
    print(number(["a", "b", "c"]))
    
    # Test case 3: Single line
    print(number(["hello"]))
    
    # Test case 4: Empty strings
    print(number(["", ""]))
    
    # Test case 5: Multiple lines with special characters
    print(number(["Line with spaces", "123", "Special!@#"]))
