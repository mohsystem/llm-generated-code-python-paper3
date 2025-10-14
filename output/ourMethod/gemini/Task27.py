from typing import List

def find_outlier(integers: List[int]) -> int:
    """
    Finds the outlier number in a list where all numbers are either even or odd, except for one.

    Args:
        integers: The input list of integers, which must have a length of at least 3.

    Returns:
        The outlier integer.
    
    Raises:
        ValueError: If the list has fewer than 3 elements or if no outlier is found.
    """
    if not isinstance(integers, list) or len(integers) < 3:
        raise ValueError("Input must be a list with at least 3 elements.")
    
    # Use bitwise AND with 1 to check parity (0 for even, 1 for odd).
    # This works for both positive and negative integers.
    parities = [n & 1 for n in integers[:3]]
    
    # If the sum of parities of the first three is >= 2, the majority is odd.
    if sum(parities) >= 2:
        majority_is_odd = True
    else:
        majority_is_odd = False
        
    for num in integers:
        is_odd = (num & 1) == 1
        if majority_is_odd:
            # If majority is odd, outlier is even
            if not is_odd:
                return num
        else:
            # If majority is even, outlier is odd
            if is_odd:
                return num
    
    # This part should be unreachable based on the problem description.
    raise ValueError("No outlier found, which violates problem constraints.")

def main():
    """Main function with test cases."""
    # Test Case 1: Outlier is odd
    test1 = [2, 4, 0, 100, 4, 11, 2602, 36]
    print(f"Test 1: {test1} -> {find_outlier(test1)}")

    # Test Case 2: Outlier is even
    test2 = [160, 3, 1719, 19, 11, 13, -21]
    print(f"Test 2: {test2} -> {find_outlier(test2)}")

    # Test Case 3: Minimal array, outlier is even
    test3 = [1, 1, 2]
    print(f"Test 3: {test3} -> {find_outlier(test3)}")
    
    # Test Case 4: Negative numbers involved, outlier is odd
    test4 = [2, 6, 8, -10, 3]
    print(f"Test 4: {test4} -> {find_outlier(test4)}")

    # Test Case 5: Edge values, outlier is odd (2147483647)
    test5 = [2147483647, 0, 2]
    print(f"Test 5: {[2147483647, 0, 2]} -> {find_outlier(test5)}")

if __name__ == "__main__":
    main()