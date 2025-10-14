
def sort_array(arr):
    """\n    Sorts an array of integers in ascending order\n    :param arr: The input list to be sorted\n    :return: A new sorted list (original list remains unchanged)\n    """
    # Input validation - prevent type errors
    if arr is None:
        return []
    
    if not isinstance(arr, list):
        return []
    
    # Validate all elements are integers
    try:
        # Create a copy to avoid modifying the original list
        result = arr.copy()
        
        # Use built-in sort which is secure and efficient
        result.sort()
        
        return result
    except (TypeError, AttributeError):
        return []


def main():
    """Main function with test cases"""
    # Test case 1: Normal array
    test1 = [5, 2, 8, 1, 9]
    print(f"Test 1: {sort_array(test1)}")
    
    # Test case 2: Already sorted array
    test2 = [1, 2, 3, 4, 5]
    print(f"Test 2: {sort_array(test2)}")
    
    # Test case 3: Reverse sorted array
    test3 = [9, 7, 5, 3, 1]
    print(f"Test 3: {sort_array(test3)}")
    
    # Test case 4: Array with duplicates
    test4 = [4, 2, 7, 2, 9, 4]
    print(f"Test 4: {sort_array(test4)}")
    
    # Test case 5: Empty array
    test5 = []
    print(f"Test 5: {sort_array(test5)}")


if __name__ == "__main__":
    main()
