
def merge_sorted_arrays(arr1, arr2):
    if arr1 is None:
        arr1 = []
    if arr2 is None:
        arr2 = []
    
    result = []
    i, j = 0, 0
    
    while i < len(arr1) and j < len(arr2):
        if arr1[i] <= arr2[j]:
            result.append(arr1[i])
            i += 1
        else:
            result.append(arr2[j])
            j += 1
    
    while i < len(arr1):
        result.append(arr1[i])
        i += 1
    
    while j < len(arr2):
        result.append(arr2[j])
        j += 1
    
    return result


if __name__ == "__main__":
    # Test case 1: Normal case
    arr1 = [1, 3, 5, 7]
    arr2 = [2, 4, 6, 8]
    result1 = merge_sorted_arrays(arr1, arr2)
    print("Test 1:", result1)
    
    # Test case 2: One empty array
    arr3 = []
    arr4 = [1, 2, 3]
    result2 = merge_sorted_arrays(arr3, arr4)
    print("Test 2:", result2)
    
    # Test case 3: Different lengths
    arr5 = [1, 5, 9]
    arr6 = [2, 3, 4, 6, 7, 8]
    result3 = merge_sorted_arrays(arr5, arr6)
    print("Test 3:", result3)
    
    # Test case 4: Duplicate elements
    arr7 = [1, 3, 5, 5]
    arr8 = [2, 3, 5, 6]
    result4 = merge_sorted_arrays(arr7, arr8)
    print("Test 4:", result4)
    
    # Test case 5: Negative numbers
    arr9 = [-5, -3, 0, 2]
    arr10 = [-4, -1, 1, 3]
    result5 = merge_sorted_arrays(arr9, arr10)
    print("Test 5:", result5)
