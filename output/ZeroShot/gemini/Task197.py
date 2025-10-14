import random
import math
from typing import List

class Solution:
    """
    Solution class to generate a uniform random point inside a circle.
    """
    def __init__(self, radius: float, x_center: float, y_center: float):
        """
        Initializes the object with the radius of the circle and the position of the center.
        :param radius: The radius of the circle.
        :param x_center: The x-coordinate of the center of the circle.
        :param y_center: The y-coordinate of the center of the circle.
        """
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center

    def randPoint(self) -> List[float]:
        """
        Returns a random point inside the circle.
        The point distribution is uniform.
        :return: A random point as a list [x, y].
        """
        # Use polar coordinates with inverse transform sampling for uniform distribution
        r_sqrt = math.sqrt(random.random()) # For uniform distribution of area
        r = self.radius * r_sqrt
        theta = random.random() * 2 * math.pi
        
        x = self.x_center + r * math.cos(theta)
        y = self.y_center + r * math.sin(theta)
        
        return [x, y]

# Main execution block with test cases
if __name__ == '__main__':
    # Test Case 1
    print("Test Case 1 (radius=1.0, center=(0.0, 0.0)):")
    sol1 = Solution(1.0, 0.0, 0.0)
    for _ in range(5):
        print(sol1.randPoint())
    
    # Test Case 2
    print("\nTest Case 2 (radius=10.0, center=(5.0, -7.5)):")
    sol2 = Solution(10.0, 5.0, -7.5)
    for _ in range(5):
        print(sol2.randPoint())

    # Test Case 3
    print("\nTest Case 3 (radius=0.1, center=(100.0, 100.0)):")
    sol3 = Solution(0.1, 100, 100)
    for _ in range(5):
        print(sol3.randPoint())

    # Test Case 4
    print("\nTest Case 4 (radius=1e8, center=(-1e7, 1e7)):")
    sol4 = Solution(1e8, -1e7, 1e7)
    for _ in range(5):
        print(sol4.randPoint())

    # Test Case 5
    print("\nTest Case 5 (radius=1.0, center=(1.0, 1.0)):")
    sol5 = Solution(1.0, 1.0, 1.0)
    for _ in range(5):
        print(sol5.randPoint())