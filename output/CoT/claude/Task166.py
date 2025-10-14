
def posNegSort(arr):
    if arr is None or len(arr) == 0:
        return []
    
    # Extract positive numbers and sort them
    positives = sorted([num for num in arr if num > 0])
    
    # Create result list and place sorted positives back
    result = []
    pos_index = 0
    
    for num in arr:
        if num < 0:
            result.append(num)
        else:
            result.append(positives[pos_index])
            pos_index += 1
    
    return result

if __name__ == "__main__":
    # Test case 1
    test1 = [6, 3, -2, 5, -8, 2, -2]
    print("Test 1:", posNegSort(test1))
    
    # Test case 2
    test2 = [6, 5, 4, -1, 3, 2, -1, 1]
    print("Test 2:", posNegSort(test2))
    
    # Test case 3
    test3 = [-5, -5, -5, -5, 7, -5]
    print("Test 3:", posNegSort(test3))
    
    # Test case 4
    test4 = []
    print("Test 4:", posNegSort(test4))
    
    # Test case 5
    test5 = [10, -3, 5, -1, 8, -7, 3]
    print("Test 5:", posNegSort(test5))
