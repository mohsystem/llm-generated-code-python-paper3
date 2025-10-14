
def heap_sort(arr):
    n = len(arr)
    
    # Build max heap
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i)
    
    # Extract elements from heap one by one
    for i in range(n - 1, 0, -1):
        # Move current root to end
        arr[0], arr[i] = arr[i], arr[0]
        
        # Heapify the reduced heap
        heapify(arr, i, 0)
    
    return arr

def heapify(arr, n, i):
    largest = i
    left = 2 * i + 1
    right = 2 * i + 2
    
    # If left child is larger than root
    if left < n and arr[left] > arr[largest]:
        largest = left
    
    # If right child is larger than largest so far
    if right < n and arr[right] > arr[largest]:
        largest = right
    
    # If largest is not root
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]
        
        # Recursively heapify the affected sub-tree
        heapify(arr, n, largest)

if __name__ == "__main__":
    # Test case 1
    arr1 = [12, 11, 13, 5, 6, 7]
    print("Test 1 - Original:", arr1.copy())
    heap_sort(arr1)
    print("Test 1 - Sorted:", arr1)
    
    # Test case 2
    arr2 = [64, 34, 25, 12, 22, 11, 90]
    print("\\nTest 2 - Original:", arr2.copy())
    heap_sort(arr2)
    print("Test 2 - Sorted:", arr2)
    
    # Test case 3
    arr3 = [5, 4, 3, 2, 1]
    print("\\nTest 3 - Original:", arr3.copy())
    heap_sort(arr3)
    print("Test 3 - Sorted:", arr3)
    
    # Test case 4
    arr4 = [1]
    print("\\nTest 4 - Original:", arr4.copy())
    heap_sort(arr4)
    print("Test 4 - Sorted:", arr4)
    
    # Test case 5
    arr5 = [-5, 10, -3, 0, 8, -20, 15]
    print("\\nTest 5 - Original:", arr5.copy())
    heap_sort(arr5)
    print("Test 5 - Sorted:", arr5)
