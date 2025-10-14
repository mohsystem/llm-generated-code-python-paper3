from collections import deque
from typing import List

def max_sliding_window(nums: List[int], k: int) -> List[int]:
    """
    Finds the maximum value in a sliding window of size k.

    :param nums: The input list of integers.
    :param k: The size of the sliding window.
    :return: A list containing the maximum of each sliding window.
    """
    if not nums or k <= 0 or k > len(nums):
        return []

    n = len(nums)
    result = []
    
    # Deque stores indices of elements in the current window.
    # The indices point to values in decreasing order.
    dq = deque()

    for i in range(n):
        # Remove indices from the front of the deque that are out of the current window.
        if dq and dq[0] <= i - k:
            dq.popleft()

        # Maintain the decreasing order of values in the deque.
        # Remove indices from the back whose corresponding values are smaller than the current element.
        while dq and nums[dq[-1]] < nums[i]:
            dq.pop()

        # Add the current index to the back of the deque.
        dq.append(i)

        # Once the window is full (i.e., we have processed at least k elements),
        # the maximum for the current window is at the front of the deque.
        if i >= k - 1:
            result.append(nums[dq[0]])
            
    return result

if __name__ == "__main__":
    # Test Case 1
    nums1 = [1, 3, -1, -3, 5, 3, 6, 7]
    k1 = 3
    print("Test Case 1:")
    print(f"Input: nums = {nums1}, k = {k1}")
    print(f"Output: {max_sliding_window(nums1, k1)}")
    print()

    # Test Case 2
    nums2 = [1]
    k2 = 1
    print("Test Case 2:")
    print(f"Input: nums = {nums2}, k = {k2}")
    print(f"Output: {max_sliding_window(nums2, k2)}")
    print()

    # Test Case 3
    nums3 = [1, -1]
    k3 = 1
    print("Test Case 3:")
    print(f"Input: nums = {nums3}, k = {k3}")
    print(f"Output: {max_sliding_window(nums3, k3)}")
    print()

    # Test Case 4
    nums4 = [7, 2, 4]
    k4 = 2
    print("Test Case 4:")
    print(f"Input: nums = {nums4}, k = {k4}")
    print(f"Output: {max_sliding_window(nums4, k4)}")
    print()

    # Test Case 5
    nums5 = [1, 3, 1, 2, 0, 5]
    k5 = 3
    print("Test Case 5:")
    print(f"Input: nums = {nums5}, k = {k5}")
    print(f"Output: {max_sliding_window(nums5, k5)}")
    print()