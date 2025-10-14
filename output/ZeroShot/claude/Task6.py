
def find_uniq(arr):
    if arr is None or len(arr) < 3:
        raise ValueError("Array must contain at least 3 numbers")
    
    # Compare first three elements to determine which is the unique one
    if arr[0] == arr[1]:
        # arr[0] and arr[1] are the same, so they represent the repeated value
        for i in range(2, len(arr)):
            if arr[i] != arr[0]:
                return arr[i]
        return arr[0]  # Should not reach here given problem constraints
    elif arr[0] == arr[2]:
        # arr[0] and arr[2] are the same, so arr[1] is unique
        return arr[1]
    else:
        # arr[1] and arr[2] must be the same, so arr[0] is unique
        return arr[0]


if __name__ == "__main__":
    # Test case 1
    result1 = find_uniq([1, 1, 1, 2, 1, 1])
    print(f"Test 1: {result1} (Expected: 2.0)")
    
    # Test case 2
    result2 = find_uniq([0, 0, 0.55, 0, 0])
    print(f"Test 2: {result2} (Expected: 0.55)")
    
    # Test case 3
    result3 = find_uniq([5, 5, 5, 5, 10])
    print(f"Test 3: {result3} (Expected: 10.0)")
    
    # Test case 4
    result4 = find_uniq([3.14, 2.71, 2.71, 2.71])
    print(f"Test 4: {result4} (Expected: 3.14)")
    
    # Test case 5
    result5 = find_uniq([-1, -1, -1, -5, -1, -1, -1])
    print(f"Test 5: {result5} (Expected: -5.0)")
