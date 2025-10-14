def merge_arrays(arr1, arr2):
    """
    Merges two sorted integer arrays into a single sorted array.

    :param arr1: The first sorted list of integers.
    :param arr2: The second sorted list of integers.
    :return: A new list containing all elements from arr1 and arr2 in sorted order.
    """
    n1 = len(arr1)
    n2 = len(arr2)
    result = [0] * (n1 + n2)
    i, j, k = 0, 0, 0

    # Traverse both arrays and insert the smaller element into the result
    while i < n1 and j < n2:
        if arr1[i] <= arr2[j]:
            result[k] = arr1[i]
            i += 1
        else:
            result[k] = arr2[j]
            j += 1
        k += 1

    # Copy remaining elements of arr1, if any
    while i < n1:
        result[k] = arr1[i]
        i += 1
        k += 1

    # Copy remaining elements of arr2, if any
    while j < n2:
        result[k] = arr2[j]
        j += 1
        k += 1

    return result

if __name__ == "__main__":
    # Test Case 1
    arr1_1 = [1, 3, 5]
    arr1_2 = [2, 4, 6]
    print(f"Test Case 1: {merge_arrays(arr1_1, arr1_2)}")

    # Test Case 2
    arr2_1 = [10, 20, 30]
    arr2_2 = []
    print(f"Test Case 2: {merge_arrays(arr2_1, arr2_2)}")

    # Test Case 3
    arr3_1 = []
    arr3_2 = [5, 15, 25]
    print(f"Test Case 3: {merge_arrays(arr3_1, arr3_2)}")

    # Test Case 4
    arr4_1 = [1, 5, 9, 10]
    arr4_2 = [2, 3, 8]
    print(f"Test Case 4: {merge_arrays(arr4_1, arr4_2)}")

    # Test Case 5
    arr5_1 = [1, 2, 3]
    arr5_2 = [4, 5, 6]
    print(f"Test Case 5: {merge_arrays(arr5_1, arr5_2)}")