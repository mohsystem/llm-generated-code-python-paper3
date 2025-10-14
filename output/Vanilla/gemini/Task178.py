import collections

def shortestSubarray(nums, k):
    n = len(nums)
    prefix_sums = [0] * (n + 1)
    for i in range(n):
        prefix_sums[i + 1] = prefix_sums[i] + nums[i]

    min_length = n + 1
    dq = collections.deque()

    for i, p_sum in enumerate(prefix_sums):
        # Check for valid subarrays ending at i-1
        while dq and p_sum - prefix_sums[dq[0]] >= k:
            min_length = min(min_length, i - dq.popleft())

        # Maintain monotonic property of the deque (increasing prefix sums)
        while dq and p_sum <= prefix_sums[dq[-1]]:
            dq.pop()
        
        dq.append(i)

    return min_length if min_length != n + 1 else -1

if __name__ == '__main__':
    # Test Case 1
    nums1 = [1]
    k1 = 1
    print(f"Test Case 1: {shortestSubarray(nums1, k1)}")

    # Test Case 2
    nums2 = [1, 2]
    k2 = 4
    print(f"Test Case 2: {shortestSubarray(nums2, k2)}")

    # Test Case 3
    nums3 = [2, -1, 2]
    k3 = 3
    print(f"Test Case 3: {shortestSubarray(nums3, k3)}")

    # Test Case 4
    nums4 = [84, -37, 32, 40, 95]
    k4 = 167
    print(f"Test Case 4: {shortestSubarray(nums4, k4)}")
    
    # Test Case 5
    nums5 = [-28, 81, -20, 28, -29]
    k5 = 89
    print(f"Test Case 5: {shortestSubarray(nums5, k5)}")