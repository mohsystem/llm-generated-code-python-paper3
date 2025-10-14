import collections

class Task178:
    def shortestSubarray(self, nums: list[int], k: int) -> int:
        n = len(nums)
        prefix_sums = [0] * (n + 1)
        for i in range(n):
            prefix_sums[i + 1] = prefix_sums[i] + nums[i]

        min_length = n + 1
        dq = collections.deque()

        for i, p_sum in enumerate(prefix_sums):
            # Check if any subarray ending at i-1 satisfies the condition
            while dq and p_sum - prefix_sums[dq[0]] >= k:
                min_length = min(min_length, i - dq.popleft())
            
            # Maintain the monotonic (increasing) property of the deque
            while dq and p_sum <= prefix_sums[dq[-1]]:
                dq.pop()
            
            dq.append(i)

        return min_length if min_length <= n else -1

if __name__ == '__main__':
    solver = Task178()
    # Test Case 1
    nums1 = [1]
    k1 = 1
    print(f"Test Case 1: {solver.shortestSubarray(nums1, k1)}")

    # Test Case 2
    nums2 = [1, 2]
    k2 = 4
    print(f"Test Case 2: {solver.shortestSubarray(nums2, k2)}")

    # Test Case 3
    nums3 = [2, -1, 2]
    k3 = 3
    print(f"Test Case 3: {solver.shortestSubarray(nums3, k3)}")

    # Test Case 4
    nums4 = [84, -37, 32, 40, 95]
    k4 = 167
    print(f"Test Case 4: {solver.shortestSubarray(nums4, k4)}")
    
    # Test Case 5
    nums5 = [-28, 81, -20, 28, -29]
    k5 = 89
    print(f"Test Case 5: {solver.shortestSubarray(nums5, k5)}")