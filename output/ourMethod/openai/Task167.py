from decimal import Decimal, ROUND_HALF_UP
import math
from typing import List

def cube_diagonal(volume: float) -> float:
    if not isinstance(volume, (int, float)):
        raise ValueError("Volume must be a number.")
    v = float(volume)
    if not math.isfinite(v) or v < 0.0:
        raise ValueError("Volume must be a finite non-negative number.")
    side = v ** (1.0 / 3.0)
    diag = side * math.sqrt(3.0)
    rounded = Decimal(diag).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return float(rounded)

if __name__ == "__main__":
    tests: List[float] = [8.0, 343.0, 1157.625, 0.0, 1.0]
    for v in tests:
        res = cube_diagonal(v)
        print(f"cubeDiagonal({v:.6f}) = {res:.2f}")