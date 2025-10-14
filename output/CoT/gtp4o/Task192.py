# Chain-of-Through Process:
# 1. Problem understanding: Implement xor_game to decide winner with optimal play.
# 2. Security requirements: Validate input type/length defensively.
# 3. Secure coding generation: Pure function without side effects.
# 4. Code review: XOR accumulation and length parity check.
# 5. Secure code output: Final function with tests.

from typing import List

def xor_game(nums: List[int]) -> bool:
    if nums is None or len(nums) == 0:
        # XOR of no elements is 0; starting player wins.
        return True
    x = 0
    for v in nums:
        x ^= (v & 0xFFFF)
    if x == 0:
        return True
    return (len(nums) % 2) == 0

def _run_test(nums: List[int]) -> None:
    print(f"nums={nums} -> {xor_game(nums)}")

if __name__ == "__main__":
    _run_test([1, 1, 2])   # false
    _run_test([0, 1])      # true
    _run_test([1, 2, 3])   # true
    _run_test([1])         # false
    _run_test([1, 1])      # true