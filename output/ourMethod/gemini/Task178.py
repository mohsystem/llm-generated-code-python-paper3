import collections
from typing import List

def shortest_subarray(nums: List[int], k: int) -> int:
    """
    Finds the length of the shortest non-empty subarray with a sum of at least k.

    :param nums: The input integer list.
    :param k: The target sum.
    :return: The length of the shortest subarray, or -1 if no such subarray exists.
    """
    n = len(nums)
    prefix_sums = [0] * (n + 1)
    for i in range(n):
        prefix_sums[i + 1] = prefix_sums[i] + nums[i]

    min_length = n + 1
    # Deque stores indices of the prefix_sums list.
    deque = collections.deque()

    for j, p_j in enumerate(prefix_sums):
        # Condition 1: Find a valid subarray.
        # If p_j - prefix_sums[deque[0]] >= k, we found a subarray.
        # We want the shortest, so we check from the left of the deque.
        while deque and p_j - prefix_sums[deque[0]] >= k:
            min_length = min(min_length, j - deque.popleft())

        # Condition 2: Maintain a monotonically increasing prefix_sums in the deque.
        # If p_j <= prefix_sums[deque[-1]], the last element is no longer optimal.
        # A future subarray starting at index j would be shorter and have a smaller or equal prefix sum.
        while deque and p_j <= prefix_sums[deque[-1]]:
            deque.pop()
            
        deque.append(j)

    return min_length if min_length <= n else -1

if __name__ == '__main__':
    # Test case 1: Basic case
    nums1 = [1]
    k1 = 1
    print(f"Test 1: {shortest_subarray(nums1, k1)}")  # Expected: 1

    # Test case 2: No such subarray
    nums2 = [1, 2]
    k2 = 4
    print(f"Test 2: {shortest_subarray(nums2, k2)}")  # Expected: -1

    # Test case 3: With negative numbers
    nums3 = [2, -1, 2]
    k3 = 3
    print(f"Test 3: {shortest_subarray(nums3, k3)}")  # Expected: 3

    # Test case 4: More complex case
    nums4 = [84, -37, 32, 40, 95]
    k4 = 167
    print(f"Test 4: {shortest_subarray(nums4, k4)}")  # Expected: 3

    # Test case 5: All negative numbers
    nums5 = [-1, -2, -3]
    k5 = 1
    print(f"Test 5: {shortest_subarray(nums5, k5)}")  # Expected: -1