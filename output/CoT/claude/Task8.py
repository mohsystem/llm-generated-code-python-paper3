
def find_missing_letter(array):
    # Input validation
    if array is None or len(array) < 2:
        raise ValueError("Invalid input array")
    
    # Iterate through the array and find the missing letter
    for i in range(len(array) - 1):
        # Check if the next character is not consecutive
        if ord(array[i + 1]) - ord(array[i]) != 1:
            # Return the missing letter
            return chr(ord(array[i]) + 1)
    
    # This should never happen with valid input
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
