# Chain-of-Through process in code generation:
# 1) Problem understanding: compute remaining people on a bus given pairs [on, off].
# 2) Security requirements: validate inputs, avoid negative totals, robust to None/empty.
# 3) Secure coding generation: use Python ints (arbitrary precision), validate values.
# 4) Code review: ensure checks for pair structure and non-negativity.
# 5) Secure code output: final code with 5 tests.

from typing import Iterable, Tuple

def people_on_bus(stops: Iterable[Tuple[int, int]]) -> int:
    total = 0
    if stops is None:
        return 0
    for idx, pair in enumerate(stops):
        if pair is None or len(pair) < 2:
            on, off = 0, 0
        else:
            on, off = int(pair[0]), int(pair[1])
        if on < 0 or off < 0:
            raise ValueError("Negative values are not allowed.")
        total = total + on - off
        if total < 0:
            raise ValueError("Bus population would become negative.")
    return total

if __name__ == "__main__":
    t1 = [(10, 0), (3, 5), (5, 8)]  # 5
    t2 = [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)]  # 17
    t3 = []  # 0
    t4 = [(0, 0)]  # 0
    t5 = [(1_000_000_000_000, 0),
          (2_000_000_000_000, 500_000_000_000),
          (3_000_000_000_000, 1_000_000_000_000)]  # 4_500_000_000_000

    tests = [t1, t2, t3, t4, t5]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {people_on_bus(t)}")