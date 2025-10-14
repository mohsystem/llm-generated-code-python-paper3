
def heapify(arr, n, i):
    """Heapify a subtree rooted at index i"""
    largest = i
    left = 2 * i + 1
    right = 2 * i + 2

    # Check if left child exists and is greater than root
    if left < n and arr[left] > arr[largest]:
        largest = left

    # Check if right child exists and is greater than largest so far
    if right < n and arr[right] > arr[largest]:
        largest = right

    # If largest is not root, swap and continue heapifying
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]
        heapify(arr, n, largest)


def heap_sort(arr):
    """Main heap sort function"""
    if arr is None or len(arr) <= 1:
        return arr

    # Create a copy to avoid modifying original array
    result = arr.copy()
    n = len(result)

    # Build max heap
    for i in range(n // 2 - 1, -1, -1):
        heapify(result, n, i)

    # Extract elements from heap one by one
    for i in range(n - 1, 0, -1):
        # Move current root to end
        result[0], result[i] = result[i], result[0]
        # Heapify the reduced heap
        heapify(result, i, 0)

    return result


if __name__ == "__main__":
    # Test case 1: Random integers
    test1 = [64, 34, 25, 12, 22, 11, 90]
    print(f"Test 1 - Input: {test1}")
    print(f"Test 1 - Output: {heap_sort(test1)}")

    # Test case 2: Already sorted array
    test2 = [1, 2, 3, 4, 5]
    print(f"\\nTest 2 - Input: {test2}")
    print(f"Test 2 - Output: {heap_sort(test2)}")

    # Test case 3: Reverse sorted array
    test3 = [9, 7, 5, 3, 1]
    print(f"\\nTest 3 - Input: {test3}")
    print(f"Test 3 - Output: {heap_sort(test3)}")

    # Test case 4: Array with duplicates
    test4 = [5, 2, 8, 2, 9, 1, 5, 5]
    print(f"\\nTest 4 - Input: {test4}")
    print(f"Test 4 - Output: {heap_sort(test4)}")

    # Test case 5: Single element array
    test5 = [42]
    print(f"\\nTest 5 - Input: {test5}")
    print(f"Test 5 - Output: {heap_sort(test5)}")
