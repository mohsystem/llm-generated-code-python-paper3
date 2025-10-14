import collections
from typing import List

def max_sliding_window(nums: List[int], k: int) -> List[int]:
    """
    Finds the maximum value in a sliding window of size k.

    Args:
        nums: The input list of integers.
        k: The size of the sliding window.

    Returns:
        A list containing the maximum of each sliding window.
    """
    if not nums or k <= 0 or k > len(nums):
        return []

    result = []
    # Deque stores indices of elements from nums
    dq = collections.deque()
    n = len(nums)

    for i in range(n):
        # 1. Remove indices from the front that are out of the current window
        if dq and dq[0] <= i - k:
            dq.popleft()

        # 2. Remove indices from the back whose corresponding elements are smaller 
        #    than the current element. This maintains a deque of indices whose 
        #    elements are in decreasing order.
        while dq and nums[dq[-1]] < nums[i]:
            dq.pop()

        # 3. Add the current index to the back
        dq.append(i)

        # 4. Once the window is full, the maximum is at the front of the deque
        if i >= k - 1:
            result.append(nums[dq[0]])

    return result

if __name__ == '__main__':
    # Test Case 1
    nums1 = [1, 3, -1, -3, 5, 3, 6, 7]
    k1 = 3
    output1 = max_sliding_window(nums1, k1)
    print(f"Test Case 1: {output1}")  # Expected: [3, 3, 5, 5, 6, 7]

    # Test Case 2
    nums2 = [1]
    k2 = 1
    output2 = max_sliding_window(nums2, k2)
    print(f"Test Case 2: {output2}")  # Expected: [1]

    # Test Case 3
    nums3 = [1, -1]
    k3 = 1
    output3 = max_sliding_window(nums3, k3)
    print(f"Test Case 3: {output3}")  # Expected: [1, -1]

    # Test Case 4
    nums4 = [9, 11]
    k4 = 2
    output4 = max_sliding_window(nums4, k4)
    print(f"Test Case 4: {output4}")  # Expected: [11]

    # Test Case 5
    nums5 = [7, 2, 4]
    k5 = 2
    output5 = max_sliding_window(nums5, k5)
    print(f"Test Case 5: {output5}")  # Expected: [7, 4]