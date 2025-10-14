import math
import secrets
from typing import List, Tuple

class Solution:
    def __init__(self, radius: float, x_center: float, y_center: float) -> None:
        if not (math.isfinite(radius) and math.isfinite(x_center) and math.isfinite(y_center)):
            raise ValueError("Inputs must be finite numbers.")
        if radius <= 0.0:
            raise ValueError("Radius must be > 0.")
        self.radius = float(radius)
        self.x_center = float(x_center)
        self.y_center = float(y_center)
        self._rng = secrets.SystemRandom()

    def randPoint(self) -> List[float]:
        u = self._rng.random()
        v = self._rng.random()
        r = math.sqrt(u) * self.radius
        theta = 2.0 * math.pi * v
        x = self.x_center + r * math.cos(theta)
        y = self.y_center + r * math.sin(theta)
        return [x, y]

def main() -> None:
    # 5 test cases
    tests = [
        Solution(1.0, 0.0, 0.0),
        Solution(2.5, 3.0, -4.0),
        Solution(10.0, -100.0, 100.0),
        Solution(0.5, 1e5, -1e5),
        Solution(1e8, 1e7, -1e7),
    ]
    for i, sol in enumerate(tests, 1):
        print(f"Test {i}: {sol.randPoint()}")

if __name__ == "__main__":
    main()