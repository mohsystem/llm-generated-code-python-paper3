
from typing import List, Optional


def find_missing_number(arr: List[int]) -> int:
    """\n    Finds the missing number in an array of unique integers from 1 to n.\n    Uses sum formula to avoid overflow issues.\n    \n    Args:\n        arr: List of unique integers with one number missing\n        \n    Returns:\n        The missing number, or -1 if input is invalid\n    """
    # Validate input
    if arr is None or len(arr) == 0:
        return -1
    
    # Array length + 1 gives us n (since one number is missing)
    n = len(arr) + 1
    
    # Validate n is within reasonable bounds
    if n < 1:
        return -1
    
    # Calculate expected sum using formula: n * (n + 1) / 2
    expected_sum = (n * (n + 1)) // 2
    
    # Calculate actual sum of array elements
    actual_sum = 0
    for num in arr:
        # Validate each number is within range [1, n]
        if not isinstance(num, int) or num < 1 or num > n:
            return -1
        actual_sum += num
    
    # The difference is the missing number
    missing = expected_sum - actual_sum
    
    # Validate result is within range
    if missing < 1 or missing > n:
        return -1
    
    return missing


def main() -> None:
    """Test the find_missing_number function with 5 test cases."""
    # Test case 1: Missing number is 5
    test1 = [1, 2, 3, 4, 6, 7, 8, 9, 10]
    print(f"Test 1 - Array: {test1}")
    print(f"Missing number: {find_missing_number(test1)}")
    print()
    
    # Test case 2: Missing number is 1
    test2 = [2, 3, 4, 5]
    print(f"Test 2 - Array: {test2}")
    print(f"Missing number: {find_missing_number(test2)}")
    print()
    
    # Test case 3: Missing number is 10
    test3 = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    print(f"Test 3 - Array: {test3}")
    print(f"Missing number: {find_missing_number(test3)}")
    print()
    
    # Test case 4: Small array, missing 2
    test4 = [1]
    print(f"Test 4 - Array: {test4}")
    print(f"Missing number: {find_missing_number(test4)}")
    print()
    
    # Test case 5: Missing number is 3
    test5 = [1, 2, 4, 5, 6]
    print(f"Test 5 - Array: {test5}")
    print(f"Missing number: {find_missing_number(test5)}")


if __name__ == "__main__":
    main()
