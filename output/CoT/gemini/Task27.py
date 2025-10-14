def find_outlier(integers):
    """
    Finds the outlier number in a list where all numbers are either even or odd, except for one.

    :param integers: The input list of integers (length >= 3).
    :return: The outlier integer.
    """
    # Since the list has at least 3 elements, we can determine the majority
    # parity by checking the first three elements.
    # Using (n & 1) is 0 for even, 1 for odd.
    parity_samples = [(n & 1) for n in integers[:3]]
    
    # If the sum is 2 or 3, majority is odd. If sum is 0 or 1, majority is even.
    if sum(parity_samples) >= 2:
        # Majority is odd, so we are looking for the single even number.
        for num in integers:
            if (num & 1) == 0:
                return num
    else:
        # Majority is even, so we are looking for the single odd number.
        for num in integers:
            if (num & 1) != 0:
                return num
    
    # This part should be unreachable given the problem constraints.
    return None

if __name__ == '__main__':
    # Test Case 1: Odd outlier
    test1 = [2, 4, 0, 100, 4, 11, 2602, 36]
    print(f"Test Case 1: {test1} -> {find_outlier(test1)}")

    # Test Case 2: Even outlier
    test2 = [160, 3, 1719, 19, 11, 13, -21]
    print(f"Test Case 2: {test2} -> {find_outlier(test2)}")

    # Test Case 3: Even outlier at the beginning
    test3 = [8, 1, 3, 5, 7, 9]
    print(f"Test Case 3: {test3} -> {find_outlier(test3)}")

    # Test Case 4: Odd outlier at the end
    test4 = [2, 4, 6, 8, 10, 11]
    print(f"Test Case 4: {test4} -> {find_outlier(test4)}")

    # Test Case 5: Even outlier in the middle
    test5 = [1, 3, 5, 2, 7, 9]
    print(f"Test Case 5: {test5} -> {find_outlier(test5)}")