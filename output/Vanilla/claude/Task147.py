
import heapq

def find_kth_largest(nums, k):
    min_heap = []
    
    for num in nums:
        heapq.heappush(min_heap, num)
        if len(min_heap) > k:
            heapq.heappop(min_heap)
    
    return min_heap[0]

if __name__ == "__main__":
    # Test case 1
    nums1 = [3, 2, 1, 5, 6, 4]
    k1 = 2
    print(f"Test 1: {find_kth_largest(nums1, k1)}")  # Expected: 5
    
    # Test case 2
    nums2 = [3, 2, 3, 1, 2, 4, 5, 5, 6]
    k2 = 4
    print(f"Test 2: {find_kth_largest(nums2, k2)}")  # Expected: 4
    
    # Test case 3
    nums3 = [7, 10, 4, 3, 20, 15]
    k3 = 3
    print(f"Test 3: {find_kth_largest(nums3, k3)}")  # Expected: 10
    
    # Test case 4
    nums4 = [1]
    k4 = 1
    print(f"Test 4: {find_kth_largest(nums4, k4)}")  # Expected: 1
    
    # Test case 5
    nums5 = [-1, -5, -3, -7, -2]
    k5 = 2
    print(f"Test 5: {find_kth_largest(nums5, k5)}")  # Expected: -2
