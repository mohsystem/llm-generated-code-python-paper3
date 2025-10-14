def xorGame(nums):
    if nums is None:
        raise ValueError("Input array cannot be None")
    x = 0
    for v in nums:
        x ^= v
    if x == 0:
        return True
    return len(nums) % 2 == 0

if __name__ == "__main__":
    tests = [
        [1, 1, 2],  # False
        [0, 1],     # True
        [1, 2, 3],  # True
        [5],        # False
        [2, 2]      # True
    ]
    for t in tests:
        print(f"Input: {t} -> {str(xorGame(t)).lower()}")