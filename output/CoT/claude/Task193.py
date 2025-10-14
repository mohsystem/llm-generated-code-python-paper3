
def xor_game(nums):
    if not nums:
        return False
    
    xor = 0
    for num in nums:
        xor ^= num
    
    return xor == 0 or len(nums) % 2 == 0

if __name__ == "__main__":
    # Test case 1
    print(xor_game([1, 1, 2]))  # False
    
    # Test case 2
    print(xor_game([0, 1]))  # True
    
    # Test case 3
    print(xor_game([1, 2, 3]))  # True
    
    # Test case 4
    print(xor_game([1]))  # False
    
    # Test case 5
    print(xor_game([2, 2, 2, 2]))  # True
