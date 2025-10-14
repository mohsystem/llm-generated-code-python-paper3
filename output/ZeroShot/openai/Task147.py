import heapq

def kth_largest(nums, k):
    if nums is None or not isinstance(nums, list):
        raise ValueError("Input array must be a list.")
    if not all(isinstance(x, int) for x in nums):
        raise ValueError("All elements in the array must be integers.")
    n = len(nums)
    if k < 1 or k > n:
        raise ValueError("k must be between 1 and the length of the array.")
    min_heap = []
    for v in nums:
        if len(min_heap) < k:
            heapq.heappush(min_heap, v)
        else:
            if v > min_heap[0]:
                heapq.heapreplace(min_heap, v)
    return min_heap[0]

if __name__ == "__main__":
    tests = [
        ([3, 2, 1, 5, 6, 4], 2),
        ([3, 2, 3, 1, 2, 4, 5, 5, 6], 4),
        ([-1, -1], 2),
        ([7], 1),
        ([3, 2, 1, 5, 6, 4], 10),  # invalid
    ]
    for i, (arr, k) in enumerate(tests, 1):
        try:
            print(f"Test {i} result: {kth_largest(arr, k)}")
        except ValueError as e:
            print(f"Test {i} error: {e}")