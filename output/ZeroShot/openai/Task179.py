from collections import deque

def max_sliding_window(nums, k):
    if not isinstance(nums, list) or not isinstance(k, int):
        return []
    n = len(nums)
    if n == 0 or k <= 0 or k > n:
        return []
    dq = deque()
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

if __name__ == "__main__":
    tests = [
        ([1,3,-1,-3,5,3,6,7], 3),
        ([1], 1),
        ([9,11], 2),
        ([4,-2], 1),
        ([7,2,4], 2),
    ]
    for nums, k in tests:
        print(max_sliding_window(nums, k))