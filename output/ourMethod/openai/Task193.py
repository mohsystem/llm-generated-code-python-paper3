from typing import List

def alice_wins(nums: List[int]) -> bool:
    # Validate inputs per constraints
    if not isinstance(nums, list) or len(nums) < 1 or len(nums) > 1000:
        return False  # fail closed on invalid input
    xor_val = 0
    for v in nums:
        if not isinstance(v, int) or v < 0 or v >= (1 << 16):
            return False  # fail closed on invalid value
        xor_val ^= v
    # If xor is 0 at start, Alice wins. Else Alice wins iff length is even.
    return xor_val == 0 or (len(nums) % 2 == 0)

def _run_test(nums: List[int]) -> None:
    print(f"nums={nums} -> {alice_wins(nums)}")

if __name__ == "__main__":
    # 5 test cases
    _run_test([1, 1, 2])     # False
    _run_test([0, 1])        # True
    _run_test([1, 2, 3])     # True
    _run_test([5])           # False
    _run_test([1, 1, 1])     # False