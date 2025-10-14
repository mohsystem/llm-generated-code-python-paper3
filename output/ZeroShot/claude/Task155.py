
def heap_sort(arr):
    if arr is None or len(arr) <= 1:
        return arr
    
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
    # Test case 1: Regular unsorted array
    arr1 = [12, 11, 13, 5, 6, 7]
    heap_sort(arr1)
    print("Test 1:", arr1)
    
    # Test case 2: Already sorted array
    arr2 = [1, 2, 3, 4, 5]
    heap_sort(arr2)
    print("Test 2:", arr2)
    
    # Test case 3: Reverse sorted array
    arr3 = [9, 7, 5, 3, 1]
    heap_sort(arr3)
    print("Test 3:", arr3)
    
    # Test case 4: Array with duplicates
    arr4 = [5, 2, 8, 2, 9, 1, 5]
    heap_sort(arr4)
    print("Test 4:", arr4)
    
    # Test case 5: Single element array
    arr5 = [42]
    heap_sort(arr5)
    print("Test 5:", arr5)
