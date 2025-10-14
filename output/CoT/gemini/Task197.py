import random
import math
from typing import List

class Solution:
    def __init__(self, radius: float, x_center: float, y_center: float):
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center

    def randPoint(self) -> List[float]:
        """
        Generates a random point uniformly inside the circle.
        """
        # Generate a random angle and a random length, then convert to cartesian
        # The square root is necessary for uniform distribution over the area
        angle = random.uniform(0, 2 * math.pi)
        length = self.radius * math.sqrt(random.uniform(0, 1))
        
        x = self.x_center + length * math.cos(angle)
        y = self.y_center + length * math.sin(angle)
        
        return [x, y]

if __name__ == "__main__":
    print("Python Output:")

    # Test Case 1: Unit circle at origin
    print("\nTest Case 1: radius=1.0, center=(0.0, 0.0)")
    sol1 = Solution(1.0, 0.0, 0.0)
    for _ in range(5):
        print(sol1.randPoint())

    # Test Case 2: Larger circle with offset center
    print("\nTest Case 2: radius=10.0, center=(5.0, -5.0)")
    sol2 = Solution(10.0, 5.0, -5.0)
    for _ in range(5):
        print(sol2.randPoint())

    # Test Case 3: Small radius
    print("\nTest Case 3: radius=0.1, center=(1.0, 1.0)")
    sol3 = Solution(0.1, 1.0, 1.0)
    for _ in range(5):
        print(sol3.randPoint())

    # Test Case 4: Large radius and coordinates
    print("\nTest Case 4: radius=1000.0, center=(-100.0, 200.0)")
    sol4 = Solution(1000.0, -100.0, 200.0)
    for _ in range(5):
        print(sol4.randPoint())
    
    # Test Case 5: Zero center, different radius
    print("\nTest Case 5: radius=5.0, center=(0.0, 0.0)")
    sol5 = Solution(5.0, 0.0, 0.0)
    for _ in range(5):
        print(sol5.randPoint())