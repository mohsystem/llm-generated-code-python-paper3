from collections import deque

def max_sliding_window(nums, k):
    n = len(nums)
    if k == 0 or n == 0:
        return []
    dq = deque()  # indices
    res = []
    for i, v in enumerate(nums):
        while dq and nums[dq[-1]] <= v:
            dq.pop()
        dq.append(i)
        if dq[0] <= i - k:
            dq.popleft()
        if i >= k - 1:
            res.append(nums[dq[0]])
    return res

if __name__ == "__main__":
    tests = [
        ([1,3,-1,-3,5,3,6,7], 3),
        ([1], 1),
        ([9,8,7,6,5], 2),
        ([-1,-3,-5,-2,-1], 3),
        ([4,2,12,11,-5,6,2], 4),
    ]
    for nums, k in tests:
        print(max_sliding_window(nums, k))