
import random
import math

class Solution:
    def __init__(self, radius, x_center, y_center):
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center
    
    def randPoint(self):
        # Use square root to ensure uniform distribution
        r = math.sqrt(random.random()) * self.radius
        theta = random.random() * 2 * math.PI
        
        x = self.x_center + r * math.cos(theta)
        y = self.y_center + r * math.sin(theta)
        
        return [x, y]


def main():
    # Test case 1
    solution1 = Solution(1.0, 0.0, 0.0)
    print("Test 1:")
    for i in range(3):
        point = solution1.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
    
    # Test case 2
    solution2 = Solution(10.0, 5.0, -7.5)
    print("\\nTest 2:")
    for i in range(3):
        point = solution2.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
    
    # Test case 3
    solution3 = Solution(0.01, 0.0, 0.0)
    print("\\nTest 3:")
    for i in range(3):
        point = solution3.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
    
    # Test case 4
    solution4 = Solution(100.0, -50.0, 50.0)
    print("\\nTest 4:")
    for i in range(3):
        point = solution4.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
    
    # Test case 5
    solution5 = Solution(5.0, 10.0, 10.0)
    print("\\nTest 5:")
    for i in range(3):
        point = solution5.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")


if __name__ == "__main__":
    main()
