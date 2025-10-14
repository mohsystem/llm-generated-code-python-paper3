import random
import math

class Solution:
    def __init__(self, radius: float, x_center: float, y_center: float):
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center

    def randPoint(self):
        u = random.random()
        r = math.sqrt(u) * self.radius
        theta = 2.0 * math.pi * random.random()
        x = self.x_center + r * math.cos(theta)
        y = self.y_center + r * math.sin(theta)
        return [x, y]

def main():
    tests = [
        Solution(1.0, 0.0, 0.0),
        Solution(2.0, 1.0, 1.0),
        Solution(0.5, -2.0, -3.0),
        Solution(10.0, 5.0, -7.0),
        Solution(3.0, 100.0, 200.0),
    ]
    for s in tests:
        print(s.randPoint())

if __name__ == "__main__":
    main()