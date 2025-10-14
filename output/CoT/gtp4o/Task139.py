# Step 1-5: Secure implementation to compute area of a circle from radius.
import math
import sys

PI = math.pi

def compute_area(radius: float) -> float:
    # Validate input: finite and non-negative
    try:
        r = float(radius)
    except Exception:
        return float('nan')
    if not math.isfinite(r) or r < 0.0:
        return float('nan')
    # Prevent overflow for extremely large radii
    limit = math.sqrt(sys.float_info.max / PI)
    if abs(r) > limit:
        return float('inf')
    return PI * r * r

# 5 test cases
if __name__ == "__main__":
    tests = [0.0, 1.0, 2.5, 10.0, 12345.678]
    for r in tests:
        area = compute_area(r)
        print(f"radius={r:.6f} -> area={area:.15f}")