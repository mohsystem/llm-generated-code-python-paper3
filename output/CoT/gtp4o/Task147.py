import heapq

# Step 1 & 2: Understand and secure - validate inputs
def find_kth_largest(nums, k):
    if nums is None:
        raise ValueError("Input list must not be None.")
    n = len(nums)
    if k < 1 or k > n:
        raise ValueError("k must be between 1 and the length of the list.")

    # Step 3: Secure coding - use a min-heap of size k
    min_heap = []
    for num in nums:
        if len(min_heap) < k:
            heapq.heappush(min_heap, num)
        else:
            if num > min_heap[0]:
                heapq.heapreplace(min_heap, num)
    # Step 4: min_heap has size k; top is kth largest
    return min_heap[0]

# Step 5: Main with 5 test cases
if __name__ == "__main__":
    tests = [
        ([3, 2, 1, 5, 6, 4], 2),
        ([3, 2, 3, 1, 2, 4, 5, 5, 6], 4),
        ([-1, -3, -2, -4, -5], 2),
        ([7], 1),
        ([9, 9, 8, 7, 6, 5], 3),
    ]
    for i, (arr, k) in enumerate(tests, 1):
        res = find_kth_largest(arr, k)
        print(f"Test {i} -> kth largest: {res}")