
def find_outlier(integers):
    even_count = 0
    odd_count = 0
    last_even = 0
    last_odd = 0
    
    # Check first 3 elements to determine which type is the outlier
    for i in range(3):
        if integers[i] % 2 == 0:
            even_count += 1
            last_even = integers[i]
        else:
            odd_count += 1
            last_odd = integers[i]
    
    # Determine if we're looking for even or odd outlier
    looking_for_even = even_count < odd_count
    
    # If we already found the outlier in first 3 elements
    if looking_for_even and even_count == 1:
        return last_even
    if not looking_for_even and odd_count == 1:
        return last_odd
    
    # Search rest of array
    for i in range(3, len(integers)):
        if looking_for_even:
            if integers[i] % 2 == 0:
                return integers[i]
        else:
            if integers[i] % 2 != 0:
                return integers[i]
    
    return 0

if __name__ == "__main__":
    # Test case 1
    test1 = [2, 4, 0, 100, 4, 11, 2602, 36]
    print(f"Test 1: {find_outlier(test1)}")  # Expected: 11
    
    # Test case 2
    test2 = [160, 3, 1719, 19, 11, 13, -21]
    print(f"Test 2: {find_outlier(test2)}")  # Expected: 160
    
    # Test case 3
    test3 = [2, 4, 6, 8, 10, 3]
    print(f"Test 3: {find_outlier(test3)}")  # Expected: 3
    
    # Test case 4
    test4 = [1, 3, 5, 7, 9, 2]
    print(f"Test 4: {find_outlier(test4)}")  # Expected: 2
    
    # Test case 5
    test5 = [-1, -3, -5, 0]
    print(f"Test 5: {find_outlier(test5)}")  # Expected: 0
