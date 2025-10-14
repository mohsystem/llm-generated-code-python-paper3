def find_missing_letter(chars):
    for i in range(len(chars) - 1):
        if ord(chars[i+1]) != ord(chars[i]) + 1:
            return chr(ord(chars[i]) + 1)
    # This part should not be reachable given the problem constraints
    return ""

if __name__ == "__main__":
    # Test Case 1
    test1 = ['a','b','c','d','f']
    print(f"Test Case 1: {test1} -> {find_missing_letter(test1)}")
    
    # Test Case 2
    test2 = ['O','Q','R','S']
    print(f"Test Case 2: {test2} -> {find_missing_letter(test2)}")

    # Test Case 3
    test3 = ['x','z']
    print(f"Test Case 3: {test3} -> {find_missing_letter(test3)}")
    
    # Test Case 4
    test4 = ['g','h','i','j','l']
    print(f"Test Case 4: {test4} -> {find_missing_letter(test4)}")

    # Test Case 5
    test5 = ['A','B','C','E']
    print(f"Test Case 5: {test5} -> {find_missing_letter(test5)}")