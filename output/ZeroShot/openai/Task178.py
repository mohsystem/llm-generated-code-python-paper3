from collections import deque

def shortest_subarray(nums, k):
    if not nums:
        return -1
    n = len(nums)
    prefix = [0] * (n + 1)
    for i in range(n):
        prefix[i + 1] = prefix[i] + nums[i]

    dq = deque()
    ans = n + 1
    for i in range(n + 1):
        while dq and prefix[i] - prefix[dq[0]] >= k:
            ans = min(ans, i - dq.popleft())
        while dq and prefix[i] <= prefix[dq[-1]]:
            dq.pop()
        dq.append(i)

    return ans if ans <= n else -1

def main():
    tests = [
        ([1], 1),
        ([1, 2], 4),
        ([2, -1, 2], 3),
        ([84, -37, 32, 40, 95], 167),
        ([17, 85, 93, -45, -21], 150),
    ]
    for nums, k in tests:
        print(shortest_subarray(nums, k))

if __name__ == "__main__":
    main()