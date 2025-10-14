def xorGame(nums):
    if nums is None:
        return False
    total = 0
    for v in nums:
        total ^= v & 0xFFFF
    if total == 0:
        return True
    return len(nums) % 2 == 0

def _run_test(nums):
    print(f"{nums} -> {xorGame(nums)}")

if __name__ == "__main__":
    _run_test([1, 1, 2])
    _run_test([0, 1])
    _run_test([1, 2, 3])
    _run_test([5])
    _run_test([1, 2])