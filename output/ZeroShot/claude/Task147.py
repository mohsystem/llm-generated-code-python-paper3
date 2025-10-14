
import heapq

def find_kth_largest(nums, k):
    if not nums or k <= 0 or k > len(nums):
        raise ValueError("Invalid input")
    
    min_heap = []
    
    for num in nums:
        heapq.heappush(min_heap, num)
        if len(min_heap) > k:
            heapq.heappop(min_heap)
    
    return min_heap[0]

if __name__ == "__main__":
    # Test case 1
    arr1 = [3, 2, 1, 5, 6, 4]
    k1 = 2
    print(f"Test 1: {find_kth_largest(arr1, k1)} (Expected: 5)")
    
    # Test case 2
    arr2 = [3, 2, 3, 1, 2, 4, 5, 5, 6]
    k2 = 4
    print(f"Test 2: {find_kth_largest(arr2, k2)} (Expected: 4)")
    
    # Test case 3
    arr3 = [1]
    k3 = 1
    print(f"Test 3: {find_kth_largest(arr3, k3)} (Expected: 1)")
    
    # Test case 4
    arr4 = [7, 10, 4, 3, 20, 15]
    k4 = 3
    print(f"Test 4: {find_kth_largest(arr4, k4)} (Expected: 10)")
    
    # Test case 5
    arr5 = [-1, -5, -3, -2, -4]
    k5 = 2
    print(f"Test 5: {find_kth_largest(arr5, k5)} (Expected: -2)")
