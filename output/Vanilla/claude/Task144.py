
def merge_sorted_arrays(arr1, arr2):
    n1 = len(arr1)
    n2 = len(arr2)
    result = []
    
    i = 0
    j = 0
    
    while i < n1 and j < n2:
        if arr1[i] <= arr2[j]:
            result.append(arr1[i])
            i += 1
        else:
            result.append(arr2[j])
            j += 1
    
    while i < n1:
        result.append(arr1[i])
        i += 1
    
    while j < n2:
        result.append(arr2[j])
        j += 1
    
    return result


if __name__ == "__main__":
    # Test case 1
    arr1_1 = [1, 3, 5, 7]
    arr2_1 = [2, 4, 6, 8]
    print("Test 1:", merge_sorted_arrays(arr1_1, arr2_1))
    
    # Test case 2
    arr1_2 = [1, 2, 3]
    arr2_2 = [4, 5, 6]
    print("Test 2:", merge_sorted_arrays(arr1_2, arr2_2))
    
    # Test case 3
    arr1_3 = [1, 5, 9]
    arr2_3 = [2, 3, 4, 6, 7, 8]
    print("Test 3:", merge_sorted_arrays(arr1_3, arr2_3))
    
    # Test case 4
    arr1_4 = []
    arr2_4 = [1, 2, 3]
    print("Test 4:", merge_sorted_arrays(arr1_4, arr2_4))
    
    # Test case 5
    arr1_5 = [-5, -2, 0, 3]
    arr2_5 = [-3, -1, 2, 4, 6]
    print("Test 5:", merge_sorted_arrays(arr1_5, arr2_5))
