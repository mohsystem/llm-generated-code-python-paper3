# Task29 - Python Implementation
# Chain-of-Through process:
# 1) Problem understanding: Return indices of two numbers that sum to target.
# 2) Security requirements: avoid global mutable state, validate minimal inputs.
# 3) Secure coding generation: use dict for O(1) lookups, no unsafe eval/IO.
# 4) Code review: handle edge cases, ensure distinct indices.
# 5) Secure code output: final function with tests.

from typing import List, Tuple

def two_sum(numbers: List[int], target: int) -> Tuple[int, int]:
    if numbers is None or len(numbers) < 2:
        raise ValueError("Input list must have at least two elements.")
    seen = {}
    for i, v in enumerate(numbers):
        comp = target - v
        if comp in seen:
            # Ensure different indices
            if seen[comp] != i:
                return (seen[comp], i)
        # Store/overwrite index for current value
        seen[v] = i
    # As per problem constraints, a solution always exists
    raise RuntimeError("No solution found, input violated problem constraints.")

if __name__ == "__main__":
    tests = [
        ([1, 2, 3], 4),       # any valid, e.g., (0,2)
        ([3, 2, 4], 6),       # (1,2)
        ([2, 7, 11, 15], 9),  # (0,1)
        ([0, 4, 3, 0], 0),    # (0,3)
        ([-3, 4, 3, 90], 0),  # (0,2)
    ]
    for nums, tgt in tests:
        res = two_sum(nums, tgt)
        print(res)