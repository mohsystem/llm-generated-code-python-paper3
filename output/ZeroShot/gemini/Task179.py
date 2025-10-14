from collections import deque
from typing import List

def max_sliding_window(nums: List[int], k: int) -> List[int]:
    """
    Finds the maximum value in a sliding window of size k.
    """
    # Handle edge cases based on constraints
    if not nums or k <= 0:
        return []

    n = len(nums)
    result = []
    
    # Deque stores indices. The values corresponding to these indices are in decreasing order.
    dq = deque()

    for i in range(n):
        # 1. Remove indices from the front that are out of the current window's scope
        if dq and dq[0] <= i - k:
            dq.popleft()

        # 2. Maintain the decreasing order of values in the deque.
        # Remove indices from the back whose corresponding values are smaller than the current element's value.
        while dq and nums[dq[-1]] < nums[i]:
            dq.pop()

        # 3. Add the current element's index to the deque
        dq.append(i)

        # 4. If the window has at least k elements, the front of the deque is the max.
        # Add it to the result list.
        if i >= k - 1:
            result.append(nums[dq[0]])
            
    return result

# main method for testing
if __name__ == '__main__':
    # Test Case 1
    nums1 = [1, 3, -1, -3, 5, 3, 6, 7]
    k1 = 3
    print("Test Case 1:")
    print(f"Input: nums = {nums1}, k = {k1}")
    print(f"Output: {max_sliding_window(nums1, k1)}")
    print("Expected: [3, 3, 5, 5, 6, 7]\n")

    # Test Case 2
    nums2 = [1]
    k2 = 1
    print("Test Case 2:")
    print(f"Input: nums = {nums2}, k = {k2}")
    print(f"Output: {max_sliding_window(nums2, k2)}")
    print("Expected: [1]\n")

    # Test Case 3
    nums3 = [1, -1]
    k3 = 1
    print("Test Case 3:")
    print(f"Input: nums = {nums3}, k = {k3}")
    print(f"Output: {max_sliding_window(nums3, k3)}")
    print("Expected: [1, -1]\n")

    # Test Case 4
    nums4 = [9, 10, 9, -7, -4, -8, 2, -6]
    k4 = 5
    print("Test Case 4:")
    print(f"Input: nums = {nums4}, k = {k4}")
    print(f"Output: {max_sliding_window(nums4, k4)}")
    print("Expected: [10, 10, 9, 2, 2]\n")

    # Test Case 5
    nums5 = [7, 2, 4]
    k5 = 2
    print("Test Case 5:")
    print(f"Input: nums = {nums5}, k = {k5}")
    print(f"Output: {max_sliding_window(nums5, k5)}")
    print("Expected: [7, 4]\n")