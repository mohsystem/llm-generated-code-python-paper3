# Chain-of-Through process:
# 1) Problem understanding: Generate 12 random monthly sales (0..100000), sum per quarter, print.
# 2) Security requirements: Use per-test local RNG with explicit seeding; no external input; no global mutable state.
# 3) Secure coding generation: Deterministic Random(seed), bounds-checked operations.
# 4) Code review: No unsafe operations, printing only, no resource leaks.
# 5) Secure code output: Deterministic, simple, and safe.

import random
from typing import List

def get_monthly_sales(rng: random.Random) -> int:
    # randint is inclusive on both ends
    return rng.randint(0, 100000)

def compute_quarterly_sales(seed: int) -> List[int]:
    rng = random.Random(seed)
    quarters = [0, 0, 0, 0]
    for month in range(12):
        sale = get_monthly_sales(rng)
        quarters[month // 3] += sale
    return quarters

def print_quarter_results(seed: int, quarters: List[int]) -> None:
    if quarters is None or len(quarters) != 4:
        raise ValueError("quarters must be a list of length 4")
    print(f"Seed {seed} quarterly totals:")
    for i, val in enumerate(quarters, start=1):
        print(f"  Q{i}: {val}")

if __name__ == "__main__":
    seeds = [0, 1, 42, 2025, 999999]
    for s in seeds:
        q = compute_quarterly_sales(s)
        print_quarter_results(s, q)