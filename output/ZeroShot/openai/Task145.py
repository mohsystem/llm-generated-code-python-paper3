class Task145:
    @staticmethod
    def max_subarray_sum(nums):
        if not nums:
            return 0
        current = nums[0]
        best = nums[0]
        for x in nums[1:]:
            current = max(x, current + x)
            best = max(best, current)
        return best

if __name__ == "__main__":
    tests = [
        [-2, 1, -3, 4, -1, 2, 1, -5, 4],
        [1, 2, 3, 4],
        [-1, -2, -3],
        [5, -2, 3, -1, 2],
        []  # empty array
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} input: {t} -> Max Sum: {Task145.max_subarray_sum(t)}")