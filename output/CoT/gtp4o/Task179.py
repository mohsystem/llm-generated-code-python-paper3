from collections import deque

# Steps 1-4 combined via clear logic and boundary checks
def max_sliding_window(nums, k):
    if not isinstance(nums, list) or not nums or k <= 0 or k > len(nums):
        return []
    n = len(nums)
    dq = deque()  # stores indices
    res = []

    for i in range(n):
        while dq and dq[0] <= i - k:
            dq.popleft()
        while dq and nums[dq[-1]] <= nums[i]:
            dq.pop()
        dq.append(i)
        if i >= k - 1:
            res.append(nums[dq[0]])
    return res

def _print(arr):
    print("[" + ",".join(str(x) for x in arr) + "]")

# Step 5: tests
if __name__ == "__main__":
    tests = [
        ([1,3,-1,-3,5,3,6,7], 3),
        ([1], 1),
        ([9,10,9,-7,-4,-8,2,-6], 5),
        ([1,-1], 1),
        ([7,2,4], 2),
    ]
    for nums, k in tests:
        _print(max_sliding_window(nums, k))