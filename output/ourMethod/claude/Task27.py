
def find_outlier(integers):
    # Validate input
    if not isinstance(integers, list) or len(integers) < 3:
        raise ValueError("Array must have at least 3 elements")
    
    # Validate all elements are integers
    if not all(isinstance(x, int) for x in integers):
        raise ValueError("All elements must be integers")
    
    # Count even and odd numbers in first 3 elements to determine majority
    even_count = sum(1 for x in integers[:3] if x % 2 == 0)
    odd_count = 3 - even_count
    
    # Determine if we're looking for even or odd outlier
    looking_for_even = odd_count > even_count
    
    # Find and return the outlier
    for num in integers:
        if looking_for_even and num % 2 == 0:
            return num
        elif not looking_for_even and num % 2 != 0:
            return num
    
    raise ValueError("No outlier found")


def main():
    # Test case 1: outlier is odd
    test1 = [2, 4, 0, 100, 4, 11, 2602, 36]
    print(f"Test 1: {find_outlier(test1)}")  # Expected: 11
    
    # Test case 2: outlier is even
    test2 = [160, 3, 1719, 19, 11, 13, -21]
    print(f"Test 2: {find_outlier(test2)}")  # Expected: 160
    
    # Test case 3: outlier is odd with negative numbers
    test3 = [2, 6, 8, -10, 3]
    print(f"Test 3: {find_outlier(test3)}")  # Expected: 3
    
    # Test case 4: outlier is even with negative numbers
    test4 = [1, 1, 0, 1, 1]
    print(f"Test 4: {find_outlier(test4)}")  # Expected: 0
    
    # Test case 5: larger array
    test5 = [1, 3, 5, 7, 9, 11, 13, 15, 2]
    print(f"Test 5: {find_outlier(test5)}")  # Expected: 2


if __name__ == "__main__":
    main()
