def sort_array(arr):
    """
    Sorts a list of integers in ascending order in-place.

    Args:
        arr: The list of integers to be sorted.
    """
    # Check for None or non-list types, though list.sort() handles this
    # by raising an AttributeError, which is Pythonic.
    # An empty list will be sorted correctly (i.e., remains empty).
    if isinstance(arr, list):
        arr.sort()

def main():
    # Test Case 1: General case
    arr1 = [5, 2, 8, 1, 9, 4]
    print("Test Case 1:")
    print(f"Original: {arr1}")
    sort_array(arr1)
    print(f"Sorted:   {arr1}\n")

    # Test Case 2: Already sorted
    arr2 = [1, 2, 3, 4, 5, 6]
    print("Test Case 2:")
    print(f"Original: {arr2}")
    sort_array(arr2)
    print(f"Sorted:   {arr2}\n")

    # Test Case 3: Reverse sorted
    arr3 = [10, 8, 6, 4, 2, 0]
    print("Test Case 3:")
    print(f"Original: {arr3}")
    sort_array(arr3)
    print(f"Sorted:   {arr3}\n")
    
    # Test Case 4: With duplicates and negative numbers
    arr4 = [4, -1, 5, 2, 4, -1, 0]
    print("Test Case 4:")
    print(f"Original: {arr4}")
    sort_array(arr4)
    print(f"Sorted:   {arr4}\n")

    # Test Case 5: Empty list
    arr5 = []
    print("Test Case 5:")
    print(f"Original: {arr5}")
    sort_array(arr5)
    print(f"Sorted:   {arr5}\n")

if __name__ == "__main__":
    main()