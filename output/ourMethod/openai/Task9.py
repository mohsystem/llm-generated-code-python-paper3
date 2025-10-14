from typing import List, Optional

def odd_or_even(nums: Optional[List[int]]) -> str:
    if not nums:
        return "even"
    parity = 0
    for n in nums:
        if not isinstance(n, int):
            raise ValueError("All elements must be integers")
        parity ^= (n % 2)
    return "even" if parity == 0 else "odd"


if __name__ == "__main__":
    tests = [
        [],                 # even
        [0],                # even
        [0, 1, 4],          # odd
        [0, -1, -5],        # even
        [2, 3, 5, 7],       # odd
    ]
    for t in tests:
        print(odd_or_even(t))