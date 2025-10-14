# Chain-of-Through process:
# 1) Problem understanding: For volume V of a cube, side s = V^(1/3); main diagonal d = s * sqrt(3). Round to 2 decimals.
# 2) Security requirements: Validate input as finite, non-negative.
# 3) Secure coding generation: Use math.cbrt if available (Python 3.11+); fallback to ** (1/3) with care; here we'll use pow with 1/3. Use ROUND_HALF_UP via Decimal for consistent rounding.
# 4) Code review: Ensured validation and consistent rounding.
# 5) Secure code output: Provide function and 5 test cases.

import math
from decimal import Decimal, ROUND_HALF_UP, getcontext

def cubeDiagonal(volume: float) -> float:
    if not isinstance(volume, (int, float)):
        raise TypeError("Volume must be a number.")
    if not math.isfinite(volume) or volume < 0.0:
        raise ValueError("Volume must be a non-negative finite number.")
    # Compute cube root
    try:
        side = math.cbrt(volume)  # Python 3.11+
    except AttributeError:
        # Fallback: use pow with 1/3; for non-negative volume it's safe
        side = volume ** (1.0 / 3.0)
    diagonal = side * math.sqrt(3.0)
    # Consistent rounding HALF_UP to two decimals
    getcontext().prec = 28
    rounded = Decimal(diagonal).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return float(rounded)

if __name__ == "__main__":
    tests = [8.0, 343.0, 1157.625, 1.0, 0.0]
    for v in tests:
        try:
            result = cubeDiagonal(v)
            print(f"cubeDiagonal({v:.6f}) = {result:.2f}")
        except Exception as e:
            print(f"cubeDiagonal({v:.6f}) threw: {e}")