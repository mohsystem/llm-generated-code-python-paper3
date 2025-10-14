def binary_array_to_integer(binary):
    """
    Converts a list of binary digits (0s and 1s) to its integer equivalent.

    Args:
        binary: A list of integers, where each integer is either 0 or 1.

    Returns:
        The integer representation of the binary value.

    Raises:
        ValueError: If the list contains elements other than 0 or 1.
        TypeError: If the input is not a list.
    """
    if not isinstance(binary, list):
        raise TypeError("Input must be a list.")
    
    # Using ''.join is efficient. Python's int() automatically handles
    # conversion from a base-2 string representation and supports arbitrarily
    # large integers, preventing overflow.
    num_str = ""
    for bit in binary:
        if bit == 0:
            num_str += '0'
        elif bit == 1:
            num_str += '1'
        else:
            raise ValueError("Array must contain only 0s and 1s.")
            
    return int(num_str, 2) if num_str else 0

if __name__ == "__main__":
    # 5 Test cases
    test_cases = [
        [0, 0, 0, 1],  # ==> 1
        [0, 0, 1, 0],  # ==> 2
        [0, 1, 0, 1],  # ==> 5
        [1, 0, 0, 1],  # ==> 9
        [1, 1, 1, 1]   # ==> 15
    ]

    for test_case in test_cases:
        try:
            result = binary_array_to_integer(test_case)
            print(f"Testing: {test_case} ==> {result}")
        except (ValueError, TypeError) as e:
            print(f"Error processing {test_case}: {e}")