def binary_array_to_number(arr):
    """
    Converts an array of binary digits (0s and 1s) to its integer equivalent.
    
    Args:
        arr: A list of integers, where each integer is either 0 or 1.
    
    Returns:
        The decimal integer value of the binary representation.
    """
    return int("".join(map(str, arr)), 2)

if __name__ == '__main__':
    # Test cases
    print(binary_array_to_number([0, 0, 0, 1])) # Expected: 1
    print(binary_array_to_number([0, 1, 0, 1])) # Expected: 5
    print(binary_array_to_number([1, 0, 0, 1])) # Expected: 9
    print(binary_array_to_number([1, 1, 1, 1])) # Expected: 15
    print(binary_array_to_number([1, 0, 1, 1])) # Expected: 11