from functools import reduce
from operator import xor
from typing import List

class Task192:
  """
  Solves the Chalkboard XOR Game problem.
  """
  def xorGame(self, nums: List[int]) -> bool:
    """
    Determines if Alice wins the XOR game.

    Alice wins if:
    1. The initial bitwise XOR of all numbers is 0. She wins on her first turn.
    2. The number of elements is even. In this case, if the initial XOR sum is not 0,
       Alice can always make a move that does not result in an XOR sum of 0.
       This is because for a player to be forced to lose, they must face a board
       where all elements are identical to the current XOR sum, which is only possible
       if the number of elements is odd. Since Alice always starts her turn with an
       even number of elements, she can never be forced to lose. The game will proceed
       to the end, and Bob will take the last turn, making him lose.

    Args:
      nums: The list of integers on the chalkboard.

    Returns:
      True if Alice wins, False otherwise.
    """
    # Calculate the bitwise XOR of all elements.
    # reduce(xor, nums) would also work, but a simple loop is clear.
    xor_sum = 0
    for num in nums:
        xor_sum ^= num

    if xor_sum == 0:
      return True
    
    return len(nums) % 2 == 0

# Main execution block with test cases
if __name__ == '__main__':
    solver = Task192()
    
    # Test Case 1: nums = [1,1,2], Output: false
    nums1 = [1, 1, 2]
    print(f"Test Case 1 for [1, 1, 2]: {solver.xorGame(nums1)}")

    # Test Case 2: nums = [0,1], Output: true
    nums2 = [0, 1]
    print(f"Test Case 2 for [0, 1]: {solver.xorGame(nums2)}")

    # Test Case 3: nums = [1,2,3], Output: true
    nums3 = [1, 2, 3]
    print(f"Test Case 3 for [1, 2, 3]: {solver.xorGame(nums3)}")

    # Test Case 4: n is even, xorSum != 0 -> true
    nums4 = [1, 2, 4, 8]
    print(f"Test Case 4 for [1, 2, 4, 8]: {solver.xorGame(nums4)}")

    # Test Case 5: n is odd, xorSum != 0 -> false
    nums5 = [5, 5, 5]
    print(f"Test Case 5 for [5, 5, 5]: {solver.xorGame(nums5)}")