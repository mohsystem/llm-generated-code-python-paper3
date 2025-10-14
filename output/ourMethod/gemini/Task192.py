from typing import List

def xor_game(nums: List[int]) -> bool:
    """
    Determines if Alice wins the XOR game.

    Alice wins if:
    1. The bitwise XOR of all elements is 0 at the start of her turn.
    2. The number of elements is even. If the initial XOR is not 0, she can always 
       make a move to keep the XOR non-zero. Since the total number of turns is even, 
       Bob will make the last move, making the XOR sum 0, and lose.
    
    If the number of elements is odd and the initial XOR is not 0, Alice will make
    the last move and lose.

    Args:
        nums: A list of integers on the chalkboard.

    Returns:
        True if Alice wins, False otherwise.
    """
    xor_sum = 0
    for num in nums:
        xor_sum ^= num
    
    # Alice wins if the initial XOR sum is 0 (immediate win)
    # or if the number of elements is even.
    return xor_sum == 0 or len(nums) % 2 == 0

if __name__ == "__main__":
    # Test Case 1: Example 1, Expected: false
    nums1 = [1, 1, 2]
    print(f"Input: {nums1}, Output: {xor_game(nums1)}")

    # Test Case 2: Example 2, Expected: true
    nums2 = [0, 1]
    print(f"Input: {nums2}, Output: {xor_game(nums2)}")

    # Test Case 3: Example 3, Expected: true
    nums3 = [1, 2, 3]
    print(f"Input: {nums3}, Output: {xor_game(nums3)}")

    # Test Case 4: N even, XOR non-zero. Expected: true
    nums4 = [1, 2, 3, 6]
    print(f"Input: {nums4}, Output: {xor_game(nums4)}")

    # Test Case 5: N odd, XOR non-zero. Expected: false
    nums5 = [4, 5, 2]
    print(f"Input: {nums5}, Output: {xor_game(nums5)}")