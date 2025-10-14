from typing import List

def binary_array_to_integer(binary: List[int]) -> int:
    """
    Given a list of ones and zeroes, convert the equivalent binary value to an integer.
    """
    if not binary:
        return 0
    
    number = 0
    for bit in binary:
        # Left shift the current number by 1 and add the new bit.
        number = (number << 1) | bit
    return number

if __name__ == '__main__':
    # Test Case 1
    test1 = [0, 0, 0, 1]
    print(f"Testing: {test1} ==> {binary_array_to_integer(test1)}")

    # Test Case 2
    test2 = [0, 0, 1, 0]
    print(f"Testing: {test2} ==> {binary_array_to_integer(test2)}")

    # Test Case 3
    test3 = [0, 1, 0, 1]
    print(f"Testing: {test3} ==> {binary_array_to_integer(test3)}")

    # Test Case 4
    test4 = [1, 0, 0, 1]
    print(f"Testing: {test4} ==> {binary_array_to_integer(test4)}")

    # Test Case 5
    test5 = [1, 1, 1, 1]
    print(f"Testing: {test5} ==> {binary_array_to_integer(test5)}")