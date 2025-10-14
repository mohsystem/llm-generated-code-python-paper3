
def find_uniq(arr):
    # Security: Validate input array
    if arr is None or len(arr) < 3:
        raise ValueError("Array must contain at least 3 elements")
    
    # Compare first three elements to determine which is unique
    if arr[0] == arr[1]:
        # arr[0] and arr[1] are the same
        for i in range(2, len(arr)):
            if arr[i] != arr[0]:
                return arr[i]
        return arr[2]
    elif arr[0] == arr[2]:
        # arr[0] and arr[2] are the same, arr[1] is unique
        return arr[1]
    else:
        # arr[1] and arr[2] must be the same, arr[0] is unique
        return arr[0]

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", find_uniq([1, 1, 1, 2, 1, 1]))  # Expected: 2
    
    # Test case 2
    print("Test 2:", find_uniq([0, 0, 0.55, 0, 0]))  # Expected: 0.55
    
    # Test case 3
    print("Test 3:", find_uniq([5, 5, 5, 5, 3]))  # Expected: 3
    
    # Test case 4
    print("Test 4:", find_uniq([10, 20, 20, 20]))  # Expected: 10
    
    # Test case 5
    print("Test 5:", find_uniq([-1, -1, -1, -1, 0]))  # Expected: 0
