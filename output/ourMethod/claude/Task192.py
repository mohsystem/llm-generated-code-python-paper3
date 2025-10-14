
def xor_game(nums):
    if nums is None or len(nums) < 1 or len(nums) > 1000:
        raise ValueError("Invalid input: array length must be between 1 and 1000")
    
    for num in nums:
        if not isinstance(num, int) or num < 0 or num >= 65536:
            raise ValueError("Invalid input: elements must be integers between 0 and 2^16-1")
    
    xor = 0
    for num in nums:
        xor ^= num
    
    return xor == 0 or len(nums) % 2 == 0

if __name__ == "__main__":
    # Test case 1
    test1 = [1, 1, 2]
    print(f"Test 1: {xor_game(test1)}")  # False
    
    # Test case 2
    test2 = [0, 1]
    print(f"Test 2: {xor_game(test2)}")  # True
    
    # Test case 3
    test3 = [1, 2, 3]
    print(f"Test 3: {xor_game(test3)}")  # True
    
    # Test case 4
    test4 = [1]
    print(f"Test 4: {xor_game(test4)}")  # False
    
    # Test case 5
    test5 = [2, 2, 2, 2]
    print(f"Test 5: {xor_game(test5)}")  # True
