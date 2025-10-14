def find_outlier(integers):
    """
    Finds the outlier number in a list where all numbers are either even or odd, except for one.
    
    Args:
        integers: The input list of integers (length >= 3).
    
    Returns:
        The single outlier integer.
    """
    odd_count = 0
    even_count = 0
    last_odd = 0
    last_even = 0

    for n in integers:
        if n % 2 == 0:
            even_count += 1
            last_even = n
        else:
            odd_count += 1
            last_odd = n
            
    if even_count == 1:
        return last_even
    else:
        return last_odd

if __name__ == '__main__':
    # Test Case 1: Outlier is odd
    test1 = [2, 4, 0, 100, 4, 11, 2602, 36]
    print(f"Test 1 Outlier: {find_outlier(test1)}")

    # Test Case 2: Outlier is even
    test2 = [160, 3, 1719, 19, 11, 13, -21]
    print(f"Test 2 Outlier: {find_outlier(test2)}")

    # Test Case 3: Small array, outlier is even
    test3 = [1, 1, 0, 1, 1]
    print(f"Test 3 Outlier: {find_outlier(test3)}")

    # Test Case 4: Outlier is odd, at the end
    test4 = [2, 6, 8, -10, 3]
    print(f"Test 4 Outlier: {find_outlier(test4)}")
    
    # Test Case 5: Negative numbers, outlier is even
    test5 = [-3, -5, -7, -9, 10]
    print(f"Test 5 Outlier: {find_outlier(test5)}")