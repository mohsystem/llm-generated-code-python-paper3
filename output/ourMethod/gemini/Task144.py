from typing import List, Optional

def merge_sorted_arrays(arr1: Optional[List[int]], arr2: Optional[List[int]]) -> List[int]:
    """
    Merges two sorted integer lists into a single sorted list.

    Args:
        arr1: The first sorted list. Can be None, treated as an empty list.
        arr2: The second sorted list. Can be None, treated as an empty list.

    Returns:
        A new list containing all elements from arr1 and arr2 in sorted order.
    """
    if arr1 is None:
        arr1 = []
    if arr2 is None:
        arr2 = []
        
    n1 = len(arr1)
    n2 = len(arr2)
    merged_array = [0] * (n1 + n2)
    i, j, k = 0, 0, 0

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

if __name__ == "__main__":
    # Test Case 1: General case
    arr1_1 = [1, 3, 5]
    arr1_2 = [2, 4, 6]
    print("Test Case 1:")
    print(f"Input: {arr1_1}, {arr1_2}")
    print(f"Output: {merge_sorted_arrays(arr1_1, arr1_2)}\n")

    # Test Case 2: One array is empty
    arr2_1 = [10, 20, 30]
    arr2_2 = []
    print("Test Case 2:")
    print(f"Input: {arr2_1}, {arr2_2}")
    print(f"Output: {merge_sorted_arrays(arr2_1, arr2_2)}\n")

    # Test Case 3: Both arrays are empty
    arr3_1 = []
    arr3_2 = []
    print("Test Case 3:")
    print(f"Input: {arr3_1}, {arr3_2}")
    print(f"Output: {merge_sorted_arrays(arr3_1, arr3_2)}\n")

    # Test Case 4: Arrays with different lengths
    arr4_1 = [1, 2, 9, 15]
    arr4_2 = [3, 10]
    print("Test Case 4:")
    print(f"Input: {arr4_1}, {arr4_2}")
    print(f"Output: {merge_sorted_arrays(arr4_1, arr4_2)}\n")

    # Test Case 5: Arrays with duplicate and negative numbers
    arr5_1 = [-5, 0, 5]
    arr5_2 = [-10, 0, 10]
    print("Test Case 5:")
    print(f"Input: {arr5_1}, {arr5_2}")
    print(f"Output: {merge_sorted_arrays(arr5_1, arr5_2)}\n")