from typing import List

def heapify(arr: List[int], n: int, i: int):
    """
    To heapify a subtree rooted at index i.
    n is the size of the heap.
    """
    largest = i  # Initialize largest as root
    left = 2 * i + 1
    right = 2 * i + 2

    # See if left child of root exists and is greater than root
    if left < n and arr[left] > arr[largest]:
        largest = left

    # See if right child of root exists and is greater than the largest so far
    if right < n and arr[right] > arr[largest]:
        largest = right

    # Change root, if needed
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]  # swap

        # Heapify the root of the affected subtree
        heapify(arr, n, largest)

def heap_sort(arr: List[int]):
    """
    Sorts a list of integers in-place using the Heap Sort algorithm.
    """
    if not arr or len(arr) <= 1:
        return

    n = len(arr)

    # Build a max-heap.
    # The last parent node is at index (n//2 - 1).
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i)

    # One by one extract elements
    for i in range(n - 1, 0, -1):
        arr[i], arr[0] = arr[0], arr[i]  # swap
        heapify(arr, i, 0)

if __name__ == "__main__":
    def run_test_case(test_name: str, arr: List[int]):
        print(f"--- {test_name} ---")
        # Create a copy to show the original state
        original_arr = list(arr)
        print(f"Original array: {original_arr}")
        heap_sort(arr)
        print(f"Sorted array:   {arr}")
        print()

    run_test_case("Test Case 1: General case", [12, 11, 13, 5, 6, 7])
    run_test_case("Test Case 2: Already sorted", [5, 6, 7, 11, 12, 13])
    run_test_case("Test Case 3: Reverse sorted", [13, 12, 11, 7, 6, 5])
    run_test_case("Test Case 4: Array with duplicates", [5, 12, 5, 6, 6, 13])
    
    print("--- Test Case 5: Empty and single element arrays ---")
    arr5_empty = []
    print(f"Original array (empty): {arr5_empty}")
    heap_sort(arr5_empty)
    print(f"Sorted array (empty):   {arr5_empty}")
    
    arr5_single = [42]
    print(f"Original array (single): {arr5_single}")
    heap_sort(arr5_single)
    print(f"Sorted array (single):   {arr5_single}")
    print()