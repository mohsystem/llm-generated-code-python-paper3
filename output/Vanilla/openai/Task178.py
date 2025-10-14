from collections import deque

def shortestSubarray(nums, k):
    n = len(nums)
    ps = [0] * (n + 1)
    for i in range(n):
        ps[i + 1] = ps[i] + nums[i]
    dq = deque()
    ans = n + 1
    for i in range(n + 1):
        while dq and ps[i] - ps[dq[0]] >= k:
            ans = min(ans, i - dq.popleft())
        while dq and ps[i] <= ps[dq[-1]]:
            dq.pop()
        dq.append(i)
    return ans if ans <= n else -1

if __name__ == "__main__":
    tests = [
        ([1], 1),
        ([1, 2], 4),
        ([2, -1, 2], 3),
        ([17, 85, 93, -45, -21], 150),
        ([48, 99, 37, 4, -31], 140),
    ]
    for nums, k in tests:
        print(shortestSubarray(nums, k))