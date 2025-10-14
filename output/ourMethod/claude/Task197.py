
import math
import random
from typing import List

class Solution:
    def __init__(self, radius: float, x_center: float, y_center: float):
        # Validate inputs
        if not (0 < radius <= 1e8):
            raise ValueError("Radius must be in range (0, 10^8]")
        if not (-1e7 <= x_center <= 1e7) or not (-1e7 <= y_center <= 1e7):
            raise ValueError("Center coordinates must be in range [-10^7, 10^7]")
        
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center
    
    def randPoint(self) -> List[float]:
        # Generate random angle and radius with proper distribution
        angle = random.random() * 2 * math.pi
        # Use sqrt for uniform distribution in circular area
        r = math.sqrt(random.random()) * self.radius
        
        x = self.x_center + r * math.cos(angle)
        y = self.y_center + r * math.sin(angle)
        
        return [x, y]


def main():
    # Test case 1
    solution1 = Solution(1.0, 0.0, 0.0)
    point1 = solution1.randPoint()
    print(f"Test 1: {point1}")
    
    # Test case 2
    solution2 = Solution(10.0, 5.0, -7.5)
    point2 = solution2.randPoint()
    print(f"Test 2: {point2}")
    
    # Test case 3
    solution3 = Solution(2.0, 0.0, 0.0)
    point3 = solution3.randPoint()
    print(f"Test 3: {point3}")
    
    # Test case 4
    solution4 = Solution(5.0, 10.0, 10.0)
    point4 = solution4.randPoint()
    print(f"Test 4: {point4}")
    
    # Test case 5
    solution5 = Solution(0.5, -3.0, 4.0)
    point5 = solution5.randPoint()
    print(f"Test 5: {point5}")


if __name__ == "__main__":
    main()
