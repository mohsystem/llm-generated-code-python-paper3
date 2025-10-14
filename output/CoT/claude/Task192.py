
def xor_game(nums):
    # Input validation
    if not nums:
        return False
    
    # Calculate XOR of all elements
    xor = 0
    for num in nums:
        xor ^= num
    
    # Alice wins if XOR is 0 or array length is even
    return xor == 0 or len(nums) % 2 == 0

# Test cases
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
    test5 = [2, 2]
    print(f"Test 5: {xor_game(test5)}")  # Expected: True
