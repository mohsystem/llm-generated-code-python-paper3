import math
import sys
from typing import Final

MAX_SAFE_RADIUS: Final[float] = math.sqrt(sys.float_info.max / math.pi)

def compute_circle_area(radius: float) -> float:
    if not math.isfinite(radius):
        raise ValueError("Radius must be a finite number.")
    if radius < 0.0:
        raise ValueError("Radius must be non-negative.")
    if radius > MAX_SAFE_RADIUS:
        raise ValueError("Radius too large; area would overflow.")
    return math.pi * radius * radius

if __name__ == "__main__":
    tests = [0.0, 1.0, 2.5, 1e150, -3.0]
    for r in tests:
        try:
            area = compute_circle_area(r)
            print(f"radius={r:.6f} -> area={area:.6f}")
        except ValueError as e:
            print(f"radius={r:.6f} -> error={str(e)}")