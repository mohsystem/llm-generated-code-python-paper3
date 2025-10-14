
def merge_sorted_arrays(arr1, arr2):
    # Input validation
    if arr1 is None:
        arr1 = []
    if arr2 is None:
        arr2 = []
    
    len1 = len(arr1)
    len2 = len(arr2)
    result = []
    
    i = 0
    j = 0
    
    # Merge arrays while both have elements
    while i < len1 and j < len2:
        if arr1[i] <= arr2[j]:
            result.append(arr1[i])
            i += 1
        else:
            result.append(arr2[j])
            j += 1
    
    # Copy remaining elements from arr1
    while i < len1:
        result.append(arr1[i])
        i += 1
    
    # Copy remaining elements from arr2
    while j < len2:
        result.append(arr2[j])
        j += 1
    
    return result


if __name__ == "__main__":
    # Test case 1: Normal case
    arr1 = [1, 3, 5, 7]
    arr2 = [2, 4, 6, 8]
    result1 = merge_sorted_arrays(arr1, arr2)
    print(f"Test 1: {result1}")
    
    # Test case 2: One empty array
    arr3 = []
    arr4 = [1, 2, 3]
    result2 = merge_sorted_arrays(arr3, arr4)
    print(f"Test 2: {result2}")
    
    # Test case 3: Arrays with duplicates
    arr5 = [1, 3, 3, 5]
    arr6 = [2, 3, 4]
    result3 = merge_sorted_arrays(arr5, arr6)
    print(f"Test 3: {result3}")
    
    # Test case 4: Different lengths
    arr7 = [1, 2]
    arr8 = [3, 4, 5, 6, 7]
    result4 = merge_sorted_arrays(arr7, arr8)
    print(f"Test 4: {result4}")
    
    # Test case 5: Negative numbers
    arr9 = [-5, -3, -1]
    arr10 = [-4, -2, 0, 2]
    result5 = merge_sorted_arrays(arr9, arr10)
    print(f"Test 5: {result5}")
