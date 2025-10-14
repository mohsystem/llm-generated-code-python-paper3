from typing import List
import functools
import operator

class Solution:
    def xorGame(self, nums: List[int]) -> bool:
        xor_sum = functools.reduce(operator.xor, nums, 0)
        return xor_sum == 0 or len(nums) % 2 == 0

def main():
    solver = Solution()

    # Test Case 1
    nums1 = [1, 1, 2]
    print(f"Test Case 1: nums = {nums1}, Result: {solver.xorGame(nums1)}")

    # Test Case 2
    nums2 = [0, 1]
    print(f"Test Case 2: nums = {nums2}, Result: {solver.xorGame(nums2)}")
    
    # Test Case 3
    nums3 = [1, 2, 3]
    print(f"Test Case 3: nums = {nums3}, Result: {solver.xorGame(nums3)}")
    
    # Test Case 4
    nums4 = [1, 1]
    print(f"Test Case 4: nums = {nums4}, Result: {solver.xorGame(nums4)}")
    
    # Test Case 5
    nums5 = [1, 2, 3, 4, 5, 6, 7]
    print(f"Test Case 5: nums = {nums5}, Result: {solver.xorGame(nums5)}")

if __name__ == "__main__":
    main()