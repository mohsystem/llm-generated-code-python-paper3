
def binary_array_to_int(binary: list) -> int:
    if not isinstance(binary, list):
        raise TypeError("Input must be a list")
    
    if len(binary) == 0:
        raise ValueError("Input array cannot be empty")
    
    if len(binary) > 63:
        raise ValueError("Input array length exceeds maximum supported size (63 bits)")
    
    result = 0
    
    for bit in binary:
        if not isinstance(bit, int) or (bit != 0 and bit != 1):
            raise ValueError("Array must contain only 0 or 1 values")
        result = (result << 1) | bit
    
    return result


def main():
    test_cases = [
        [0, 0, 0, 1],
        [0, 0, 1, 0],
        [0, 1, 0, 1],
        [1, 0, 0, 1],
        [1, 1, 1, 1]
    ]
    
    for test_case in test_cases:
        print(f"Input: {test_case} => Output: {binary_array_to_int(test_case)}")


if __name__ == "__main__":
    main()
