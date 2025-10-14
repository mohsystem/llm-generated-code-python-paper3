
def find_missing_letter(array):
    for i in range(len(array) - 1):
        if ord(array[i + 1]) - ord(array[i]) != 1:
            return chr(ord(array[i]) + 1)
    return ''

if __name__ == "__main__":
    # Test case 1
    test1 = ['a', 'b', 'c', 'd', 'f']
    print(f"Test 1: {find_missing_letter(test1)}")  # Expected: e
    
    # Test case 2
    test2 = ['O', 'Q', 'R', 'S']
    print(f"Test 2: {find_missing_letter(test2)}")  # Expected: P
    
    # Test case 3
    test3 = ['a', 'b', 'd', 'e']
    print(f"Test 3: {find_missing_letter(test3)}")  # Expected: c
    
    # Test case 4
    test4 = ['m', 'n', 'o', 'q', 'r']
    print(f"Test 4: {find_missing_letter(test4)}")  # Expected: p
    
    # Test case 5
    test5 = ['X', 'Z']
    print(f"Test 5: {find_missing_letter(test5)}")  # Expected: Y
