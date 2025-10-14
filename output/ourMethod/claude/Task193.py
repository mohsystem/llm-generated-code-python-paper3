
from typing import List

def xor_game(nums: List[int]) -> bool:
    if nums is None:
        raise ValueError("Input array cannot be None")
    if len(nums) < 1 or len(nums) > 1000:
        raise ValueError("Array length must be between 1 and 1000")
    
    xor_sum = 0
    for num in nums:
        if not isinstance(num, int) or num < 0 or num >= 65536:
            raise ValueError("Array elements must be integers between 0 and 65535")
        xor_sum ^= num
    
    return xor_sum == 0 or len(nums) % 2 == 0

if __name__ == "__main__":
    # Test case 1
    test1 = [1, 1, 2]
    print(f"Test 1: {xor_game(test1)}")  # Expected: False
    
    # Test case 2
    test2 = [0, 1]
    print(f"Test 2: {xor_game(test2)}")  # Expected: True
    
    # Test case 3
    test3 = [1, 2, 3]
    print(f"Test 3: {xor_game(test3)}")  # Expected: True
    
    # Test case 4
    test4 = [1]
    print(f"Test 4: {xor_game(test4)}")  # Expected: False
    
    # Test case 5
    test5 = [2, 2, 2, 2]
    print(f"Test 5: {xor_game(test5)}")  # Expected: True
