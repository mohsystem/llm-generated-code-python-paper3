import random
import math
from typing import List

class Solution:

    def __init__(self, radius: float, x_center: float, y_center: float):
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center

    def randPoint(self) -> List[float]:
        angle = 2 * math.pi * random.random()
        r = self.radius * math.sqrt(random.random())
        x = self.x_center + r * math.cos(angle)
        y = self.y_center + r * math.sin(angle)
        return [x, y]

if __name__ == '__main__':
    s1 = Solution(1.0, 0.0, 0.0)
    print(s1.randPoint())
    print(s1.randPoint())
    print(s1.randPoint())

    s2 = Solution(10.0, 5.0, -7.5)
    print(s2.randPoint())
    print(s2.randPoint())

    s3 = Solution(0.01, -100.0, 100.0)
    print(s3.randPoint())

    s4 = Solution(1000.0, 0.0, 0.0)
    print(s4.randPoint())

    s5 = Solution(2.0, 2.0, 2.0)
    print(s5.randPoint())