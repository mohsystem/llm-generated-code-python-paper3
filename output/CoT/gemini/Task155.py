def heapify(arr, n, i):
    """
    To heapify a subtree rooted with node i which is an index in arr.
    n is the size of the heap.
    """
    largest = i  # Initialize largest as root
    l = 2 * i + 1  # left = 2*i + 1
    r = 2 * i + 2  # right = 2*i + 2

    # See if left child of root exists and is greater than root
    if l < n and arr[l] > arr[largest]:
        largest = l

    # See if right child of root exists and is greater than root
    if r < n and arr[r] > arr[largest]:
        largest = r

    # Change root, if needed
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]  # swap

        # Heapify the root.
        heapify(arr, n, largest)

def heap_sort(arr):
    """
    The main function to sort an array of given size using Heap Sort.
    """
    if arr is None or len(arr) == 0:
        return arr
        
    n = len(arr)

    # Build a maxheap.
    # Since last parent will be at ((n//2)-1) we can start at that location.
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i)

    # One by one extract elements
    for i in range(n - 1, 0, -1):
        arr[i], arr[0] = arr[0], arr[i]  # swap
        heapify(arr, i, 0)
    return arr

if __name__ == "__main__":
    test_cases = [
        [12, 11, 13, 5, 6, 7],
        [5, 4, 3, 2, 1],
        [1, 2, 3, 4, 5],
        [-5, 8, -2, 0, 9, 1, -10],
        [42]
    ]

    for i, test_case in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        original_arr = list(test_case) # Make a copy to show original
        print(f"Original array: {original_arr}")
        sorted_arr = heap_sort(test_case)
        print(f"Sorted array: {sorted_arr}")
        print()