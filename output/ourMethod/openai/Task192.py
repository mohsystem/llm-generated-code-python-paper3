from typing import List

def alice_wins(nums: List[int]) -> bool:
    _validate_input(nums)
    xor_val = 0
    for v in nums:
        xor_val ^= v
    return xor_val == 0 or (len(nums) % 2 == 0)

def _validate_input(nums: List[int]) -> None:
    if nums is None:
        raise ValueError("Input list must not be None.")
    if not isinstance(nums, list):
        raise ValueError("Input must be a list of integers.")
    n = len(nums)
    if n < 1 or n > 1000:
        raise ValueError("List length must be in [1, 1000].")
    for v in nums:
        if not isinstance(v, int):
            raise ValueError("All elements must be integers.")
        if v < 0 or v >= (1 << 16):
            raise ValueError(f"Array elements must be in [0, 2^16). Found: {v}")

def _run_test(nums: List[int]) -> None:
    print(f"Input: {nums} -> {alice_wins(nums)}")

if __name__ == "__main__":
    # 5 test cases
    _run_test([1, 1, 2])   # false
    _run_test([0, 1])      # true
    _run_test([1, 2, 3])   # true
    _run_test([1])         # false
    _run_test([0])         # true