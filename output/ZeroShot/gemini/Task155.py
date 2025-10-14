def heap_sort(arr):
    """
    Sorts a list of integers using the Heap Sort algorithm.
    The function sorts the list in-place.
    
    :param arr: The list of integers to be sorted.
    """
    # A secure code should handle None or trivial inputs gracefully.
    if arr is None or len(arr) <= 1:
        return

    n = len(arr)

    # Build a max-heap from the input data.
    # We start from the last non-leaf node and move up to the root.
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i)

    # One by one, extract elements from the heap.
    for i in range(n - 1, 0, -1):
        # Move the current root (maximum value) to the end of the list.
        arr[i], arr[0] = arr[0], arr[i]
        
        # Call heapify on the reduced heap to restore the max-heap property.
        # The size of the heap is now 'i'.
        heapify(arr, i, 0)


def heapify(arr, n, i):
    """
    Helper function to heapify a subtree rooted with node i.
    
    :param arr: The list representing the heap.
    :param n: The size of the heap.
    :param i: The index of the root of the subtree to heapify.
    """
    largest = i  # Initialize largest as root
    left_child = 2 * i + 1
    right_child = 2 * i + 2

    # If the left child is larger than the root
    if left_child < n and arr[left_child] > arr[largest]:
        largest = left_child

    # If the right child is larger than the largest so far
    if right_child < n and arr[right_child] > arr[largest]:
        largest = right_child

    # If the largest element is not the root, swap them.
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]
        
        # Recursively heapify the affected sub-tree.
        heapify(arr, n, largest)


if __name__ == "__main__":
    # Test Cases
    test_cases = [
        [12, 11, 13, 5, 6, 7],      # Test Case 1: Random elements
        [],                             # Test Case 2: Empty list
        [5],                            # Test Case 3: Single element
        [1, 2, 3, 4, 5, 6],         # Test Case 4: Already sorted
        [6, 5, 4, 3, 2, 1]          # Test Case 5: Reverse sorted
    ]

    for i, test_list in enumerate(test_cases):
        arr = list(test_list) # Create a copy to sort
        print(f"Test Case {i + 1}")
        print(f"Original array: {arr}")
        heap_sort(arr)
        print(f"Sorted array:   {arr}")
        print("--------------------")