
import heapq

def find_kth_largest(nums, k):
    """Find kth largest element using min heap"""
    # Input validation
    if nums is None or len(nums) == 0:
        raise ValueError("Array cannot be None or empty")
    if k <= 0 or k > len(nums):
        raise ValueError("k must be between 1 and array length")
    
    # Use min heap of size k to maintain k largest elements
    min_heap = []
    
    for num in nums:
        heapq.heappush(min_heap, num)
        if len(min_heap) > k:
            heapq.heappop(min_heap)
    
    return min_heap[0]


def main():
    # Test case 1: Normal case
    test1 = [3, 2, 1, 5, 6, 4]
    k1 = 2
    print(f"Test 1: Array: {test1}, k={k1}")
    print(f"Result: {find_kth_largest(test1, k1)}")
    print()
    
    # Test case 2: Array with duplicates
    test2 = [3, 2, 3, 1, 2, 4, 5, 5, 6]
    k2 = 4
    print(f"Test 2: Array: {test2}, k={k2}")
    print(f"Result: {find_kth_largest(test2, k2)}")
    print()
    
    # Test case 3: k = 1 (largest element)
    test3 = [7, 10, 4, 3, 20, 15]
    k3 = 1
    print(f"Test 3: Array: {test3}, k={k3}")
    print(f"Result: {find_kth_largest(test3, k3)}")
    print()
    
    # Test case 4: k equals array length (smallest element)
    test4 = [5, 2, 8, 1, 9]
    k4 = 5
    print(f"Test 4: Array: {test4}, k={k4}")
    print(f"Result: {find_kth_largest(test4, k4)}")
    print()
    
    # Test case 5: Single element array
    test5 = [42]
    k5 = 1
    print(f"Test 5: Array: {test5}, k={k5}")
    print(f"Result: {find_kth_largest(test5, k5)}")


if __name__ == "__main__":
    main()
