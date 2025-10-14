
def xor_game(nums):
    xor = 0
    for num in nums:
        xor ^= num
    return xor == 0 or len(nums) % 2 == 0

# Test cases
if __name__ == "__main__":
    print(xor_game([1, 1, 2]))  # False
    print(xor_game([0, 1]))  # True
    print(xor_game([1, 2, 3]))  # True
    print(xor_game([1, 1]))  # True
    print(xor_game([2, 2, 2, 2]))  # True
