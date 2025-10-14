def binary_array_to_number(arr):
    """
    Given an array of ones and zeroes, convert the equivalent binary value to an integer.
    
    Args:
        arr: A list of integers (0s and 1s).
    
    Returns:
        The integer representation of the binary value.
    """
    number = 0
    for bit in arr:
        # Left shift the current number by 1 and add the new bit using bitwise OR.
        # This is equivalent to number = number * 2 + bit
        number = (number << 1) | bit
    return number

if __name__ == '__main__':
    # Test Case 1
    print(binary_array_to_number([0, 0, 0, 1]))  # Expected: 1
    # Test Case 2
    print(binary_array_to_number([0, 0, 1, 0]))  # Expected: 2
    # Test Case 3
    print(binary_array_to_number([0, 1, 0, 1]))  # Expected: 5
    # Test Case 4
    print(binary_array_to_number([1, 0, 0, 1]))  # Expected: 9
    # Test Case 5
    print(binary_array_to_number([1, 1, 1, 1]))  # Expected: 15