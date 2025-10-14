def max_subarray_sum(nums):
    if not nums:
        return 0
    current = best = nums[0]
    for x in nums[1:]:
        current = max(x, current + x)
        best = max(best, current)
    return best

if __name__ == "__main__":
    tests = [
        [-2, 1, -3, 4, -1, 2, 1, -5, 4],
        [1],
        [5, 4, -1, 7, 8],
        [-1, -2, -3, -4],
        [0, 0, 0, 0]
    ]
    for t in tests:
        print(max_subarray_sum(t))