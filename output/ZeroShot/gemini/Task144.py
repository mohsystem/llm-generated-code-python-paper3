import sys

def merge_sorted_arrays(arr1, arr2):
    """
    Merges two sorted lists of integers into a single sorted list.
    This function securely handles None inputs by treating them as empty lists.
    """
    # Handle None or empty inputs gracefully
    if not arr1:
        return list(arr2) if arr2 else []
    if not arr2:
        return list(arr1) if arr1 else []

    len1 = len(arr1)
    len2 = len(arr2)
    
    # Security: In Python, list size is limited by memory, but this check
    # prevents attempting to create a list that exceeds theoretical limits.
    # A MemoryError would likely be raised by the system anyway.
    if len1 > sys.maxsize - len2:
         raise MemoryError("Combined array size is too large")

    merged = [0] * (len1 + len2)
    i, j, k = 0, 0, 0

    # Traverse both arrays and insert the smaller element into the merged list
    while i < len1 and j < len2:
        if arr1[i] <= arr2[j]:
            merged[k] = arr1[i]
            i += 1
        else:
            merged[k] = arr2[j]
            j += 1
        k += 1

    # Copy remaining elements from arr1, if any
    while i < len1:
        merged[k] = arr1[i]
        i += 1
        k += 1

    # Copy remaining elements from arr2, if any
    while j < len2:
        merged[k] = arr2[j]
        j += 1
        k += 1
        
    return merged

if __name__ == "__main__":
    # Test Case 1: Standard merge
    arr1_1 = [1, 3, 5, 7]
    arr1_2 = [2, 4, 6, 8]
    print("Test Case 1:")
    print(f"Array 1: {arr1_1}")
    print(f"Array 2: {arr1_2}")
    print(f"Merged:  {merge_sorted_arrays(arr1_1, arr1_2)}\n")

    # Test Case 2: One array is empty
    arr2_1 = [10, 20, 30]
    arr2_2 = []
    print("Test Case 2:")
    print(f"Array 1: {arr2_1}")
    print(f"Array 2: {arr2_2}")
    print(f"Merged:  {merge_sorted_arrays(arr2_1, arr2_2)}\n")

    # Test Case 3: First array is None
    arr3_1 = None
    arr3_2 = [5, 15, 25]
    print("Test Case 3:")
    print(f"Array 1: {arr3_1}")
    print(f"Array 2: {arr3_2}")
    print(f"Merged:  {merge_sorted_arrays(arr3_1, arr3_2)}\n")

    # Test Case 4: Arrays with duplicate values and different lengths
    arr4_1 = [1, 2, 2, 5, 9]
    arr4_2 = [2, 6, 10]
    print("Test Case 4:")
    print(f"Array 1: {arr4_1}")
    print(f"Array 2: {arr4_2}")
    print(f"Merged:  {merge_sorted_arrays(arr4_1, arr4_2)}\n")
    
    # Test Case 5: Both arrays are empty
    arr5_1 = []
    arr5_2 = []
    print("Test Case 5:")
    print(f"Array 1: {arr5_1}")
    print(f"Array 2: {arr5_2}")
    print(f"Merged:  {merge_sorted_arrays(arr5_1, arr5_2)}\n")