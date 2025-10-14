# Chain-of-Through Process:
# 1) Problem understanding: compute remaining people on the bus after processing pairs of (on, off).
# 2) Security requirements: validate input types/values, keep total non-negative.
# 3) Secure coding generation: validate each stop, use Python int (unbounded).
# 4) Code review: ensure consistent behavior and safe defaults.
# 5) Secure code output: function returns non-negative count.
from typing import List, Tuple

def count_passengers(stops: List[Tuple[int, int]]) -> int:
    if stops is None:
        return 0
    total = 0
    for idx, stop in enumerate(stops):
        if not isinstance(stop, (list, tuple)) or len(stop) < 2:
            raise ValueError(f"Invalid stop format at index {idx}")
        on, off = stop[0], stop[1]
        if not isinstance(on, int) or not isinstance(off, int):
            raise ValueError(f"Stop values must be integers at index {idx}")
        if on < 0 or off < 0:
            raise ValueError(f"Negative values are not allowed at index {idx}")
        available = total + on
        if off > available:
            raise ValueError(f"More people getting off than available at index {idx}")
        total = available - off
        if total < 0:
            raise RuntimeError(f"Total passengers became negative unexpectedly at index {idx}")
    return total

if __name__ == "__main__":
    t1 = [(10, 0), (3, 5), (5, 8)]  # expected 5
    t2 = []  # expected 0
    t3 = [(0, 0)]  # expected 0
    t4 = [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)]  # expected 17
    t5 = [(5, 0), (0, 5)]  # expected 0

    print(count_passengers(t1))
    print(count_passengers(t2))
    print(count_passengers(t3))
    print(count_passengers(t4))
    print(count_passengers(t5))