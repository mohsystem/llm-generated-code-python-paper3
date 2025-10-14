from collections import deque
from typing import List

class Task179:
    def max_sliding_window(self, nums: List[int], k: int) -> List[int]:
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
        # The elements corresponding to these indices are in decreasing order.
        dq = deque()

        for i in range(n):
            # Remove indices from the front of the deque that are out of the current window.
            if dq and dq[0] <= i - k:
                dq.popleft()

            # Maintain the decreasing order property of the deque.
            # Remove indices from the back whose corresponding elements are smaller than or equal to the current element.
            while dq and nums[dq[-1]] <= nums[i]:
                dq.pop()

            # Add the current element's index to the back of the deque.
            dq.append(i)

            # Once the window is fully formed, the maximum element is at the front of the deque.
            if i >= k - 1:
                result.append(nums[dq[0]])

        return result

if __name__ == '__main__':
    solver = Task179()

    # Test Case 1
    nums1 = [1, 3, -1, -3, 5, 3, 6, 7]
    k1 = 3
    print(f"Test Case 1: nums = {nums1}, k = {k1}")
    print(f"Output: {solver.max_sliding_window(nums1, k1)}")  # Expected: [3, 3, 5, 5, 6, 7]

    # Test Case 2
    nums2 = [1]
    k2 = 1
    print(f"\nTest Case 2: nums = {nums2}, k = {k2}")
    print(f"Output: {solver.max_sliding_window(nums2, k2)}")  # Expected: [1]

    # Test Case 3
    nums3 = [1, -1]
    k3 = 1
    print(f"\nTest Case 3: nums = {nums3}, k = {k3}")
    print(f"Output: {solver.max_sliding_window(nums3, k3)}")  # Expected: [1, -1]

    # Test Case 4
    nums4 = [9, 9, 9, 9]
    k4 = 2
    print(f"\nTest Case 4: nums = {nums4}, k = {k4}")
    print(f"Output: {solver.max_sliding_window(nums4, k4)}")  # Expected: [9, 9, 9]

    # Test Case 5
    nums5 = [7, 6, 5, 4, 3, 2, 1]
    k5 = 4
    print(f"\nTest Case 5: nums = {nums5}, k = {k5}")
    print(f"Output: {solver.max_sliding_window(nums5, k5)}")  # Expected: [7, 6, 5, 4]