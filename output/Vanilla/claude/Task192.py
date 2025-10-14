
def xor_game(nums):
    xor_sum = 0
    for num in nums:
        xor_sum ^= num
    return xor_sum == 0 or len(nums) % 2 == 0

# Test cases
print(xor_game([1, 1, 2]))  # False
print(xor_game([0, 1]))     # True
print(xor_game([1, 2, 3]))  # True
print(xor_game([1, 1, 1, 1]))  # True
print(xor_game([5, 3, 6]))  # True
