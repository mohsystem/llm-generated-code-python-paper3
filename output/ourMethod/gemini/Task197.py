import math
import random
from typing import List

class Solution:

    def __init__(self, radius: float, x_center: float, y_center: float):
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center

    def randPoint(self) -> List[float]:
        # Generate a random angle uniformly in [0, 2*pi)
        angle = random.uniform(0, 2 * math.pi)
        # Generate a random distance from center, with sqrt for uniform distribution
        # random.random() returns a float in [0.0, 1.0)
        r = self.radius * math.sqrt(random.random())
        
        # Calculate coordinates using polar to Cartesian conversion
        x = self.x_center + r * math.cos(angle)
        y = self.y_center + r * math.sin(angle)
        
        return [x, y]

if __name__ == '__main__':
    # Test Case 1
    sol1 = Solution(1.0, 0.0, 0.0)
    print("Test Case 1 (R=1, C=(0,0)):")
    for _ in range(5):
        print(sol1.randPoint())
    print()

    # Test Case 2
    sol2 = Solution(10.0, 5.0, -5.0)
    print("Test Case 2 (R=10, C=(5,-5)):")
    for _ in range(5):
        print(sol2.randPoint())
    print()
    
    # Test Case 3
    sol3 = Solution(0.1, 100.0, 100.0)
    print("Test Case 3 (R=0.1, C=(100,100)):")
    for _ in range(5):
        print(sol3.randPoint())
    print()

    # Test Case 4
    sol4 = Solution(1000.0, -500.0, 200.0)
    print("Test Case 4 (R=1000, C=(-500,200)):")
    for _ in range(5):
        print(sol4.randPoint())
    print()

    # Test Case 5
    sol5 = Solution(5.0, 0.0, 0.0)
    print("Test Case 5 (R=5, C=(0,0)):")
    for _ in range(5):
        print(sol5.randPoint())
    print()