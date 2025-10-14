import math
import random

# Chain-of-Through:
# 1) Problem understanding: Sample uniformly inside a circle via r = R*sqrt(U), theta in [0, 2π).
# 2) Security requirements: Validate inputs; avoid NaN/Inf; no insecure eval or IO.
# 3) Secure coding generation: Use Python's random; avoid globals; immutable configuration.
# 4) Code review: sqrt(U) ensures uniform area distribution; include circumference points.
# 5) Secure code output: Clean API; explicit exceptions.

class Solution:
    def __init__(self, radius: float, x_center: float, y_center: float):
        if not (isinstance(radius, (int, float)) and radius > 0.0 and math.isfinite(radius)):
            raise ValueError("Radius must be a positive finite number.")
        if not (math.isfinite(x_center) and math.isfinite(y_center)):
            raise ValueError("Center coordinates must be finite numbers.")
        self._r = float(radius)
        self._xc = float(x_center)
        self._yc = float(y_center)

    def randPoint(self):
        u = random.random()  # [0,1)
        theta = random.random() * (2.0 * math.pi)  # [0,2π)
        r = math.sqrt(u) * self._r
        x = self._xc + r * math.cos(theta)
        y = self._yc + r * math.sin(theta)
        return [x, y]

def _print_point(pt):
    # simple formatting
    print(f"[{pt[0]}, {pt[1]}]")

if __name__ == "__main__":
    # 5 test cases
    s1 = Solution(1.0, 0.0, 0.0)
    s2 = Solution(3.5, 2.0, -1.0)
    s3 = Solution(10.0, 1000.0, -2000.0)
    s4 = Solution(0.0001, -0.5, 0.5)
    s5 = Solution(5.0, -100.0, 100.0)

    _print_point(s1.randPoint())
    _print_point(s2.randPoint())
    _print_point(s3.randPoint())
    _print_point(s4.randPoint())
    _print_point(s5.randPoint())