from typing import List

class Task193:
  def xorGame(self, nums: List[int]) -> bool:
    xor_sum = 0
    for num in nums:
        xor_sum ^= num
    return xor_sum == 0 or len(nums) % 2 == 0

if __name__ == "__main__":
    solver = Task193()

    # Test Case 1
    nums1 = [1, 1, 2]
    print(str(solver.xorGame(nums1)).lower())

    # Test Case 2
    nums2 = [0, 1]
    print(str(solver.xorGame(nums2)).lower())

    # Test Case 3
    nums3 = [1, 2, 3]
    print(str(solver.xorGame(nums3)).lower())

    # Test Case 4
    nums4 = [1, 2, 4, 8]
    print(str(solver.xorGame(nums4)).lower())

    # Test Case 5
    nums5 = [1, 2, 4]
    print(str(solver.xorGame(nums5)).lower())