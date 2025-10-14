from typing import List

class Task193:
    """
    Solves the Chalkboard XOR Game problem.
    """
    def xorGame(self, nums: List[int]) -> bool:
        """
        Determines if Alice wins the Chalkboard XOR Game.

        :param nums: The list of integers on the chalkboard.
        :return: True if Alice wins, False otherwise.
        """
        xor_sum = 0
        for num in nums:
            xor_sum ^= num
        
        # Alice wins if she starts with an XOR sum of 0,
        # or if the number of elements is even.
        # If n is even and xor_sum != 0, Alice can always make a move
        # such that the remaining xor_sum is not 0. Bob will be left
        # with an odd number of elements. The game continues until Bob
        # is forced to take the last element, making the xor_sum 0 and losing.
        return xor_sum == 0 or len(nums) % 2 == 0

def main():
    game = Task193()

    # Test Case 1
    nums1 = [1, 1, 2]
    print(f"Test Case 1: nums = {nums1}, Expected: False, Got: {game.xorGame(nums1)}")

    # Test Case 2
    nums2 = [0, 1]
    print(f"Test Case 2: nums = {nums2}, Expected: True, Got: {game.xorGame(nums2)}")

    # Test Case 3
    nums3 = [1, 2, 3]
    print(f"Test Case 3: nums = {nums3}, Expected: True, Got: {game.xorGame(nums3)}")

    # Test Case 4: n is even, xor_sum != 0
    nums4 = [1, 2, 3, 4] # xor_sum = 4
    print(f"Test Case 4: nums = {nums4}, Expected: True, Got: {game.xorGame(nums4)}")

    # Test Case 5: n is odd, xor_sum != 0
    nums5 = [1, 2, 4] # xor_sum = 7
    print(f"Test Case 5: nums = {nums5}, Expected: False, Got: {game.xorGame(nums5)}")

if __name__ == "__main__":
    main()