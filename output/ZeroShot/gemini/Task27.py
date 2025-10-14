def find_outlier(integers):
    """
    Finds the outlier integer in an array that is otherwise comprised of either all even or all odd integers.

    Args:
        integers: The input list of integers (length will be at least 3).
    
    Returns:
        The outlier integer N.
    """
    # According to the prompt, the length is at least 3, so direct access is safe.
    
    even_count = 0
    # Check the first three elements to determine the majority parity.
    for i in range(3):
        if integers[i] % 2 == 0:
            even_count += 1
            
    majority_is_even = even_count >= 2

    # Iterate through the array to find the single number with the opposite parity.
    for num in integers:
        if majority_is_even:
            # If the majority is even, we are looking for the single odd number.
            if num % 2 != 0:
                return num
        else:
            # If the majority is odd, we are looking for the single even number.
            if num % 2 == 0:
                return num

    # This part should be unreachable given the problem constraints.
    return None

# main block with test cases
if __name__ == '__main__':
    test1 = [2, 4, 0, 100, 4, 11, 2602, 36]
    print(f"Test 1: {test1} -> {find_outlier(test1)}")

    test2 = [160, 3, 1719, 19, 11, 13, -21]
    print(f"Test 2: {test2} -> {find_outlier(test2)}")

    test3 = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2]
    print(f"Test 3: {test3} -> {find_outlier(test3)}")

    test4 = [2, 2, 2, 2, 3, 2, 2, 2]
    print(f"Test 4: {test4} -> {find_outlier(test4)}")

    test5 = [1, -3, 5, 7, 9, -12, 11, 13]
    print(f"Test 5: {test5} -> {find_outlier(test5)}")