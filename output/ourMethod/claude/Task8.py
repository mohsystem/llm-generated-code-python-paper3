
from typing import List

def find_missing_letter(array: List[str]) -> str:
    if array is None or len(array) < 2:
        raise ValueError("Array must contain at least 2 elements")
    
    for i in range(len(array) - 1):
        current = array[i]
        next_char = array[i + 1]
        
        if not isinstance(current, str) or len(current) != 1 or not current.isalpha():
            raise ValueError("Array must contain only single letters")
        if not isinstance(next_char, str) or len(next_char) != 1 or not next_char.isalpha():
            raise ValueError("Array must contain only single letters")
        
        current_code = ord(current)
        next_code = ord(next_char)
        
        if next_code - current_code != 1:
            missing_code = current_code + 1
            missing = chr(missing_code)
            if not missing.isalpha():
                raise ValueError("Invalid sequence")
            return missing
    
    raise ValueError("No missing letter found")

if __name__ == "__main__":
    # Test case 1
    test1 = ['a', 'b', 'c', 'd', 'f']
    print(f"Test 1: {find_missing_letter(test1)}")  # Expected: e
    
    # Test case 2
    test2 = ['O', 'Q', 'R', 'S']
    print(f"Test 2: {find_missing_letter(test2)}")  # Expected: P
    
    # Test case 3
    test3 = ['m', 'n', 'p', 'q']
    print(f"Test 3: {find_missing_letter(test3)}")  # Expected: o
    
    # Test case 4
    test4 = ['A', 'B', 'D', 'E']
    print(f"Test 4: {find_missing_letter(test4)}")  # Expected: C
    
    # Test case 5
    test5 = ['x', 'z']
    print(f"Test 5: {find_missing_letter(test5)}")  # Expected: y
