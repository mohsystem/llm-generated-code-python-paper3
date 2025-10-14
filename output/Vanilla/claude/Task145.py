
def max_subarray_sum(arr):
    if not arr:
        return 0
    
    max_sum = arr[0]
    current_sum = arr[0]
    
    for i in range(1, len(arr)):
        current_sum = max(arr[i], current_sum + arr[i])
        max_sum = max(max_sum, current_sum)
    
    return max_sum


if __name__ == "__main__":
    # Test case 1: Mixed positive and negative numbers
    test1 = [-2, 1, -3, 4, -1, 2, 1, -5, 4]
    print(f"Test 1: {max_subarray_sum(test1)}")  # Expected: 6
    
    # Test case 2: All negative numbers
    test2 = [-5, -2, -8, -1, -4]
    print(f"Test 2: {max_subarray_sum(test2)}")  # Expected: -1
    
    # Test case 3: All positive numbers
    test3 = [1, 2, 3, 4, 5]
    print(f"Test 3: {max_subarray_sum(test3)}")  # Expected: 15
    
    # Test case 4: Single element
    test4 = [5]
    print(f"Test 4: {max_subarray_sum(test4)}")  # Expected: 5
    
    # Test case 5: Mix with zeros
    test5 = [-2, 0, -1, 3, -1, 2, -3, 4]
    print(f"Test 5: {max_subarray_sum(test5)}")  # Expected: 5
