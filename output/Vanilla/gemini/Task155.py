def heapify(arr, n, i):
    """
    To heapify a subtree rooted at index i.
    n is the size of the heap.
    """
    largest = i  # Initialize largest as root
    left_child = 2 * i + 1
    right_child = 2 * i + 2

    # See if left child of root exists and is greater than root
    if left_child < n and arr[left_child] > arr[largest]:
        largest = left_child

    # See if right child of root exists and is greater than the largest so far
    if right_child < n and arr[right_child] > arr[largest]:
        largest = right_child

    # Change root, if needed
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]  # swap
        # Heapify the root of the affected sub-tree
        heapify(arr, n, largest)

def heap_sort(arr):
    """
    The main function to sort an array of given size using Heap Sort.
    """
    n = len(arr)

    # Build a max-heap.
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i)

    # One by one extract elements
    for i in range(n - 1, 0, -1):
        arr[i], arr[0] = arr[0], arr[i]  # swap
        heapify(arr, i, 0)

# Main execution block
if __name__ == "__main__":
    # Test Case 1
    arr1 = [12, 11, 13, 5, 6, 7]
    print("Test Case 1:")
    print(f"Original array: {arr1}")
    heap_sort(arr1)
    print(f"Sorted array:   {arr1}\n")

    # Test Case 2
    arr2 = [5, 4, 3, 2, 1]
    print("Test Case 2:")
    print(f"Original array: {arr2}")
    heap_sort(arr2)
    print(f"Sorted array:   {arr2}\n")

    # Test Case 3
    arr3 = [1, 2, 3, 4, 5]
    print("Test Case 3:")
    print(f"Original array: {arr3}")
    heap_sort(arr3)
    print(f"Sorted array:   {arr3}\n")

    # Test Case 4
    arr4 = [10, -5, 8, 0, -1, 3]
    print("Test Case 4:")
    print(f"Original array: {arr4}")
    heap_sort(arr4)
    print(f"Sorted array:   {arr4}\n")

    # Test Case 5
    arr5 = [42]
    print("Test Case 5:")
    print(f"Original array: {arr5}")
    heap_sort(arr5)
    print(f"Sorted array:   {arr5}\n")