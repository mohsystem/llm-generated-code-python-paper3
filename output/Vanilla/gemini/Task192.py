from functools import reduce
import operator
from typing import List

def xor_game(nums: List[int]) -> bool:
    """
    Determines if Alice wins the XOR game.

    Alice wins if:
    1. The bitwise XOR of all numbers on the board is 0 at the start of her turn.
    2. The number of elements on the board is even. If the XOR sum is not 0,
       she can always make a move that doesn't result in an XOR sum of 0,
       passing the turn to Bob. Since Alice always faces an even number of
       elements and Bob an odd number, Bob is the one who might be forced
       into a losing position.
       
    Args:
        nums: The list of integers on the chalkboard.
    
    Returns:
        True if Alice wins, False otherwise.
    """
    xor_sum = reduce(operator.xor, nums, 0)
    return xor_sum == 0 or len(nums) % 2 == 0

if __name__ == "__main__":
    # Test Case 1
    nums1 = [1, 1, 2]
    print(str(xor_game(nums1)).lower()) # Expected: false

    # Test Case 2
    nums2 = [0, 1]
    print(str(xor_game(nums2)).lower()) # Expected: true

    # Test Case 3
    nums3 = [1, 2, 3]
    print(str(xor_game(nums3)).lower()) # Expected: true

    # Test Case 4
    nums4 = [6, 6, 6, 6]
    print(str(xor_game(nums4)).lower()) # Expected: true

    # Test Case 5
    nums5 = [5, 3, 2, 1]
    print(str(xor_game(nums5)).lower()) # Expected: true