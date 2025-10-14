import heapq

def find_kth_largest(nums, k):
    """
    Finds the kth largest element in a list of integers using a min-heap.

    Args:
        nums: The input list of integers.
        k: The 'k' value, representing the desired largest element rank.

    Returns:
        The kth largest element.

    Raises:
        ValueError: If the input is invalid (e.g., empty list or k is out of bounds).
    """
    # 1. Input Validation
    if not nums or k < 1 or k > len(nums):
        raise ValueError("Invalid input: list is empty or k is out of bounds.")

    # 2. Use a min-heap to maintain the k largest elements seen so far.
    # The smallest of these k elements will be at the root of the heap.
    min_heap = []
    for num in nums:
        heapq.heappush(min_heap, num)
        # If the heap size exceeds k, remove the smallest element (the root).
        if len(min_heap) > k:
            heapq.heappop(min_heap)
    
    # 3. The root of the heap is the kth largest element.
    return min_heap[0]

def main():
    # Test Case 1
    nums1 = [3, 2, 1, 5, 6, 4]
    k1 = 2
    print(f"Test Case 1: Array = {nums1}, k = {k1} -> Result: {find_kth_largest(nums1, k1)}")

    # Test Case 2
    nums2 = [3, 2, 3, 1, 2, 4, 5, 5, 6]
    k2 = 4
    print(f"Test Case 2: Array = {nums2}, k = {k2} -> Result: {find_kth_largest(nums2, k2)}")

    # Test Case 3
    nums3 = [1]
    k3 = 1
    print(f"Test Case 3: Array = {nums3}, k = {k3} -> Result: {find_kth_largest(nums3, k3)}")

    # Test Case 4
    nums4 = [7, 6, 5, 4, 3, 2, 1]
    k4 = 7
    print(f"Test Case 4: Array = {nums4}, k = {k4} -> Result: {find_kth_largest(nums4, k4)}")

    # Test Case 5
    nums5 = [99, 99]
    k5 = 1
    print(f"Test Case 5: Array = {nums5}, k = {k5} -> Result: {find_kth_largest(nums5, k5)}")

    # Invalid Input Test
    try:
        nums6 = []
        k6 = 1
        find_kth_largest(nums6, k6)
    except ValueError as e:
        print(f"Invalid Input Test: Caught expected exception -> {e}")

if __name__ == "__main__":
    main()