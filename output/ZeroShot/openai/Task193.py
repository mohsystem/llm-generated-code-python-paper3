def xor_game(nums):
    if nums is None or len(nums) == 0:
        return True
    x = 0
    for v in nums:
        x ^= v
    if x == 0:
        return True
    return (len(nums) % 2) == 0

def main():
    tests = [
        [1, 1, 2],
        [0, 1],
        [1, 2, 3],
        [0],
        [1],
    ]
    for t in tests:
        print(str(xor_game(t)).lower())

if __name__ == "__main__":
    main()