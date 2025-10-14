
def find_outlier(integers):
    even_count = 0
    odd_count = 0
    last_even = 0
    last_odd = 0
    
    # Check first 3 elements to determine the majority
    for i in range(min(3, len(integers))):
        if integers[i] % 2 == 0:
            even_count += 1
            last_even = integers[i]
        else:
            odd_count += 1
            last_odd = integers[i]
    
    # Determine if we're looking for odd or even outlier
    looking_for_odd = even_count > odd_count
    
    # If we already found the outlier in first 3 elements
    if looking_for_odd and odd_count == 1:
        return last_odd
    if not looking_for_odd and even_count == 1:
        return last_even
    
    # Search the rest of the array
    for i in range(3, len(integers)):
        if looking_for_odd and integers[i] % 2 != 0:
            return integers[i]
        if not looking_for_odd and integers[i] % 2 == 0:
            return integers[i]
    
    return 0  # Should never reach here with valid input

if __name__ == "__main__":
    # Test case 1
    test1 = [2, 4, 0, 100, 4, 11, 2602, 36]
    print(f"Test 1: {find_outlier(test1)}")  # Expected: 11
    
    # Test case 2
    test2 = [160, 3, 1719, 19, 11, 13, -21]
    print(f"Test 2: {find_outlier(test2)}")  # Expected: 160
    
    # Test case 3
    test3 = [1, 3, 5, 7, 9, 10]
    print(f"Test 3: {find_outlier(test3)}")  # Expected: 10
    
    # Test case 4
    test4 = [2, 4, 6, 8, 10, 1]
    print(f"Test 4: {find_outlier(test4)}")  # Expected: 1
    
    # Test case 5
    test5 = [-3, -5, -7, 2, -9]
    print(f"Test 5: {find_outlier(test5)}")  # Expected: 2
