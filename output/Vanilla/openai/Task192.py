def xorGame(nums):
    xor = 0
    for v in nums:
        xor ^= v
    if xor == 0:
        return True
    return len(nums) % 2 == 0

if __name__ == "__main__":
    tests = [
        [1, 1, 2],
        [0, 1],
        [1, 2, 3],
        [2],
        [1, 1],
    ]
    for t in tests:
        print(xorGame(t))