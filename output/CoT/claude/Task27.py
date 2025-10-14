
def find_outlier(array):
    # Security: Validate input to prevent errors
    if array is None or len(array) < 3:
        raise ValueError("Array must not be None and must have at least 3 elements")
    
    # Count even and odd numbers in first 3 elements to determine the pattern
    even_count = 0
    odd_count = 0
    
    # Check first 3 elements to determine if we're looking for even or odd outlier\n    for i in range(3):\n        if array[i] % 2 == 0:\n            even_count += 1\n        else:\n            odd_count += 1\n    \n    # Determine if we're looking for the odd or even outlier
    looking_for_odd = even_count > odd_count
    
    # Find and return the outlier
    for num in array:
        if looking_for_odd and num % 2 != 0:
            return num
        elif not looking_for_odd and num % 2 == 0:
            return num
    
    # This should never be reached given valid input
    raise ValueError("No outlier found in array")


if __name__ == "__main__":
    # Test case 1: Only odd number
    test1 = [2, 4, 0, 100, 4, 11, 2602, 36]
    print(f"Test 1: {find_outlier(test1)}")  # Expected: 11
    
    # Test case 2: Only even number
    test2 = [160, 3, 1719, 19, 11, 13, -21]
    print(f"Test 2: {find_outlier(test2)}")  # Expected: 160
    
    # Test case 3: Negative odd outlier
    test3 = [2, 4, 6, 8, 10, -1]
    print(f"Test 3: {find_outlier(test3)}")  # Expected: -1
    
    # Test case 4: Negative even outlier
    test4 = [1, 3, 5, 7, -2, 9]
    print(f"Test 4: {find_outlier(test4)}")  # Expected: -2
    
    # Test case 5: Zero as outlier
    test5 = [1, 3, 5, 0, 7, 9]
    print(f"Test 5: {find_outlier(test5)}")  # Expected: 0
