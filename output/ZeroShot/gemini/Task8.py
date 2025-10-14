def find_missing_letter(chars):
    """
    Finds the missing letter in a list of consecutive, increasing letters.
    The list will always be valid and have exactly one letter missing.
    
    :param chars: A list of consecutive letters with one missing.
    :return: The missing letter.
    """
    for i in range(1, len(chars)):
        # Check if the current character's ordinal value is not one greater than the previous one.
        if ord(chars[i]) != ord(chars[i-1]) + 1:
            # If not, the missing character is the character corresponding to the previous ordinal + 1.
            return chr(ord(chars[i-1]) + 1)
    # This part is unreachable given the problem constraints, but good practice for robustness.
    return ""

if __name__ == '__main__':
    # Test Case 1
    test1 = ['a','b','c','d','f']
    print(f"Test 1: {test1} -> Expected: e, Got: {find_missing_letter(test1)}")
    
    # Test Case 2
    test2 = ['O','Q','R','S']
    print(f"Test 2: {test2} -> Expected: P, Got: {find_missing_letter(test2)}")
    
    # Test Case 3
    test3 = ['x', 'z']
    print(f"Test 3: {test3} -> Expected: y, Got: {find_missing_letter(test3)}")
    
    # Test Case 4
    test4 = ['A', 'B', 'D']
    print(f"Test 4: {test4} -> Expected: C, Got: {find_missing_letter(test4)}")
    
    # Test Case 5
    test5 = ['m', 'n', 'o', 'q']
    print(f"Test 5: {test5} -> Expected: p, Got: {find_missing_letter(test5)}")