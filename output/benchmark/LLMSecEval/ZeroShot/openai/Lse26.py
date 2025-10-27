from math import isfinite
from typing import Sequence

def get_monthly_sales(sales: Sequence[float], i: int) -> float:
    if sales is None:
        raise ValueError("Sales sequence must not be None.")
    if not isinstance(i, int) or i < 0 or i >= len(sales):
        raise IndexError(f"Index out of bounds: {i}")
    val = float(sales[i])
    if not isfinite(val):
        raise ValueError(f"Sales value must be finite for index: {i}")
    return val

def compute_first_quarter_sales(sales: Sequence[float]) -> float:
    if sales is None:
        raise ValueError("Sales sequence must not be None.")
    if len(sales) < 3:
        raise ValueError("Sales sequence must contain at least 3 elements.")
    total = 0.0
    for i in range(0, 3):
        total += get_monthly_sales(sales, i)
    return total

if __name__ == "__main__":
    test_cases = [
        [120.5, 340.75, 230.25],
        [100.0, 0.0, 300.0, 400.0],
        [0.0, 0.0, 0.0],
        [1e6, 2e6, 3e6],
        [500.0, -100.0, 50.0],
    ]
    for idx, tc in enumerate(test_cases, 1):
        try:
            res = compute_first_quarter_sales(tc)
            print(f"Test {idx} input={tc} => Q1 total={res}")
        except Exception as e:
            print(f"Test {idx} input={tc} => Error: {e}")