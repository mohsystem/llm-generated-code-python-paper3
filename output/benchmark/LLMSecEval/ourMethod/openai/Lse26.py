from typing import Sequence
import math

def get_monthly_sales(sales: Sequence[float], i: int) -> float:
    if not isinstance(i, int) or i < 0 or i >= len(sales):
        return 0.0
    v = sales[i]
    try:
        fv = float(v)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(fv):
        return 0.0
    return fv

def total_first_quarter(sales: Sequence[float]) -> float:
    s = 0.0
    for i in range(3):
        s += get_monthly_sales(sales, i)
    return s

def main() -> None:
    tests = [
        [100.0, 200.0, 300.0],
        [50.5, 60.2, 70.3],
        [1000.0, 2000.0, 3000.0, 4000.0],
        [10.0],
        [-5.0, 15.0, 25.0],
    ]
    for idx, arr in enumerate(tests, 1):
        result = total_first_quarter(arr)
        print(f"Test {idx} input={arr} -> Q1 total={result:.2f}")

if __name__ == "__main__":
    main()