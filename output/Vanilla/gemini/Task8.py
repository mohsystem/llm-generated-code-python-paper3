def find_missing_letter(chars):
    for i in range(len(chars) - 1):
        # If the difference between ASCII values is not 1, a letter is missing.
        if ord(chars[i+1]) - ord(chars[i]) > 1:
            # The missing letter is the current letter's ASCII value + 1
            return chr(ord(chars[i]) + 1)
    # This part should not be reached given the problem constraints.
    return None

if __name__ == '__main__':
    # Test Case 1
    test1 = ['a', 'b', 'c', 'd', 'f']
    print(f"{test1} -> '{find_missing_letter(test1)}'")

    # Test Case 2
    test2 = ['O', 'Q', 'R', 'S']
    print(f"{test2} -> '{find_missing_letter(test2)}'")
    
    # Test Case 3
    test3 = ['x', 'z']
    print(f"{test3} -> '{find_missing_letter(test3)}'")
    
    # Test Case 4
    test4 = ['F', 'G', 'H', 'J']
    print(f"{test4} -> '{find_missing_letter(test4)}'")

    # Test Case 5
    test5 = ['m', 'n', 'o', 'q', 'r']
    print(f"{test5} -> '{find_missing_letter(test5)}'")