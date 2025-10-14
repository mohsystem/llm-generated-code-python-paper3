
def binary_array_to_int(binary_array):
    # Security: Validate input is not None
    if binary_array is None:
        raise ValueError("Input array cannot be None")
    
    # Security: Check for empty array
    if len(binary_array) == 0:
        return 0
    
    # Security: Validate array length to prevent integer overflow
    if len(binary_array) > 31:
        raise ValueError("Binary array too long, may cause integer overflow")
    
    result = 0
    
    # Security: Validate each element and convert binary to integer
    for bit in binary_array:
        # Security: Ensure only 0 or 1 values are present
        if bit != 0 and bit != 1:
            raise ValueError("Array must contain only 0 or 1 values")
        
        # Shift left and add current bit
        result = (result << 1) | bit
    
    return result


if __name__ == "__main__":
    # Test case 1
    test1 = [0, 0, 0, 1]
    print(f"Test 1: [0, 0, 0, 1] => {binary_array_to_int(test1)}")
    
    # Test case 2
    test2 = [0, 0, 1, 0]
    print(f"Test 2: [0, 0, 1, 0] => {binary_array_to_int(test2)}")
    
    # Test case 3
    test3 = [0, 1, 0, 1]
    print(f"Test 3: [0, 1, 0, 1] => {binary_array_to_int(test3)}")
    
    # Test case 4
    test4 = [1, 0, 0, 1]
    print(f"Test 4: [1, 0, 0, 1] => {binary_array_to_int(test4)}")
    
    # Test case 5
    test5 = [1, 1, 1, 1]
    print(f"Test 5: [1, 1, 1, 1] => {binary_array_to_int(test5)}")
