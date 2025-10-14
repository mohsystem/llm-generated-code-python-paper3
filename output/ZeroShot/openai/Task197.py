import math
import secrets

class Solution:
    def __init__(self, radius: float, x_center: float, y_center: float):
        if not (isinstance(radius, (int, float)) and radius > 0.0 and math.isfinite(radius)):
            raise ValueError("Radius must be positive and finite.")
        if not (math.isfinite(x_center) and math.isfinite(y_center)):
            raise ValueError("Center coordinates must be finite numbers.")
        self.radius = float(radius)
        self.x_center = float(x_center)
        self.y_center = float(y_center)
        self._rng = secrets.SystemRandom()

    def randPoint(self):
        u1 = self._rng.random()  # [0.0, 1.0)
        u2 = self._rng.random()  # [0.0, 1.0)
        r = math.sqrt(u1) * self.radius
        theta = 2.0 * math.pi * u2
        x = self.x_center + r * math.cos(theta)
        y = self.y_center + r * math.sin(theta)
        return [x, y]

if __name__ == "__main__":
    # 5 test cases (calls)
    sol = Solution(1.0, 0.0, 0.0)
    for _ in range(5):
        p = sol.randPoint()
        print(f"[{p[0]:.5f}, {p[1]:.5f}]")

    # Additional example tests
    sol2 = Solution(2.0, 3.0, -4.0)
    for _ in range(5):
        p = sol2.randPoint()
        print(f"[{p[0]:.5f}, {p[1]:.5f}]")