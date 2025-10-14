
def longest_run(arr):
    if not arr or len(arr) == 0:
        return 0
    
    if len(arr) == 1:
        return 1
    
    max_length = 1
    current_length = 1
    
    for i in range(1, len(arr)):
        if arr[i] - arr[i - 1] == 1 or arr[i] - arr[i - 1] == -1:
            current_length += 1
            max_length = max(max_length, current_length)
        else:
            current_length = 1
    
    return max_length


if __name__ == "__main__":
    # Test case 1
    test1 = [1, 2, 3, 5, 6, 7, 8, 9]
    print(f"Test 1: {longest_run(test1)} (Expected: 5)")
    
    # Test case 2
    test2 = [1, 2, 3, 10, 11, 15]
    print(f"Test 2: {longest_run(test2)} (Expected: 3)")
    
    # Test case 3
    test3 = [5, 4, 2, 1]
    print(f"Test 3: {longest_run(test3)} (Expected: 2)")
    
    # Test case 4
    test4 = [3, 5, 7, 10, 15]
    print(f"Test 4: {longest_run(test4)} (Expected: 1)")
    
    # Test case 5
    test5 = [10, 9, 8, 7, 6, 5, 4]
    print(f"Test 5: {longest_run(test5)} (Expected: 7)")
