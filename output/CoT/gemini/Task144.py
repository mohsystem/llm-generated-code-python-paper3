def merge_arrays(arr1, arr2):
    """
    Merges two sorted integer arrays into a single sorted array.

    :param arr1: The first sorted list of integers.
    :param arr2: The second sorted list of integers.
    :return: A new sorted list containing all elements from arr1 and arr2.
    """
    # Handle None or empty list edge cases
    if not arr1:
        return arr2[:] if arr2 else []
    if not arr2:
        return arr1[:]

    n1 = len(arr1)
    n2 = len(arr2)
    merged_array = [0] * (n1 + n2)

    i = 0  # Pointer for arr1
    j = 0  # Pointer for arr2
    k = 0  # Pointer for merged_array

    # Traverse both arrays and insert the smaller element into the merged array
    while i < n1 and j < n2:
        if arr1[i] <= arr2[j]:
            merged_array[k] = arr1[i]
            i += 1
        else:
            merged_array[k] = arr2[j]
            j += 1
        k += 1

    # Copy remaining elements of arr1, if any
    while i < n1:
        merged_array[k] = arr1[i]
        i += 1
        k += 1

    # Copy remaining elements of arr2, if any
    while j < n2:
        merged_array[k] = arr2[j]
        j += 1
        k += 1

    return merged_array

if __name__ == '__main__':
    # Test Case 1: Standard merge
    arr1 = [1, 3, 5, 7]
    arr2 = [2, 4, 6, 8]
    print("Test Case 1:")
    print(f"Array 1: {arr1}")
    print(f"Array 2: {arr2}")
    print(f"Merged: {merge_arrays(arr1, arr2)}\n")

    # Test Case 2: Arrays with different lengths
    arr3 = [10, 20, 30]
    arr4 = [5, 15, 25, 35, 45]
    print("Test Case 2:")
    print(f"Array 1: {arr3}")
    print(f"Array 2: {arr4}")
    print(f"Merged: {merge_arrays(arr3, arr4)}\n")

    # Test Case 3: One array is empty
    arr5 = [1, 2, 3]
    arr6 = []
    print("Test Case 3:")
    print(f"Array 1: {arr5}")
    print(f"Array 2: {arr6}")
    print(f"Merged: {merge_arrays(arr5, arr6)}\n")

    # Test Case 4: Both arrays are empty
    arr7 = []
    arr8 = []
    print("Test Case 4:")
    print(f"Array 1: {arr7}")
    print(f"Array 2: {arr8}")
    print(f"Merged: {merge_arrays(arr7, arr8)}\n")

    # Test Case 5: Arrays with negative numbers and duplicates
    arr9 = [-5, 0, 5, 5, 15]
    arr10 = [-10, -5, 10, 20]
    print("Test Case 5:")
    print(f"Array 1: {arr9}")
    print(f"Array 2: {arr10}")
    print(f"Merged: {merge_arrays(arr9, arr10)}\n")