import functools
import operator
from typing import List

def xorGame(nums: List[int]) -> bool:
    """
    Determines if Alice wins the XOR game.

    The logic is based on a game theory analysis:
    A player wins if they start their turn and the XOR sum of all numbers is 0.
    A player loses if any move they make results in an XOR sum of 0.
    An optimal player will always make a move to a state that is a losing position for the opponent, if possible.

    Let's analyze the game based on the number of elements N.
    Case 1: The initial XOR sum of all numbers is 0.
    Alice starts with an XOR sum of 0, so she wins immediately.

    Case 2: The initial XOR sum is not 0.
      - If N is even: Alice can always choose a number `x` to remove such that the new XOR sum is not 0.
        This leaves Bob with N-1 (an odd number) elements and a non-zero XOR sum.
        A game state with an odd number of elements and a non-zero XOR sum is a losing position.
        Therefore, Alice can force a win.
      - If N is odd: Any number Alice removes will leave N-1 (an even number) elements for Bob.
        A game state with an even number of elements is always a winning position for the player whose turn it is (Bob in this case).
        Therefore, Alice cannot win.

    Combining these, Alice wins if the initial XOR sum is 0, OR if the number of elements is even.

    :param nums: The list of integers on the chalkboard.
    :return: True if Alice wins, False otherwise.
    """
    xor_sum = functools.reduce(operator.xor, nums, 0)
    return xor_sum == 0 or len(nums) % 2 == 0

if __name__ == '__main__':
    # Test Case 1
    nums1 = [1, 1, 2]
    print(f"Test Case 1: nums = {nums1}")
    print(f"Output: {xorGame(nums1)}")  # Expected: False

    # Test Case 2
    nums2 = [0, 1]
    print(f"\nTest Case 2: nums = {nums2}")
    print(f"Output: {xorGame(nums2)}")  # Expected: True

    # Test Case 3
    nums3 = [1, 2, 3]
    print(f"\nTest Case 3: nums = {nums3}")
    print(f"Output: {xorGame(nums3)}")  # Expected: True

    # Test Case 4
    nums4 = [1, 1]
    print(f"\nTest Case 4: nums = {nums4}")
    print(f"Output: {xorGame(nums4)}")  # Expected: True

    # Test Case 5
    nums5 = [5, 4, 3, 2, 1]
    print(f"\nTest Case 5: nums = {nums5}")
    print(f"Output: {xorGame(nums5)}")  # Expected: False