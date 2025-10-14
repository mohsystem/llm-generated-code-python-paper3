
import random
import math

class Task197:
    def __init__(self, radius, x_center, y_center):
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center
    
    def randPoint(self):
        # Use square root to ensure uniform distribution
        r = math.sqrt(random.random()) * self.radius
        theta = random.random() * 2 * math.pi
        
        x = self.x_center + r * math.cos(theta)
        y = self.y_center + r * math.sin(theta)
        
        return [x, y]

if __name__ == "__main__":
    # Test case 1
    solution1 = Task197(1.0, 0.0, 0.0)
    print("Test case 1:")
    for _ in range(3):
        point = solution1.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
    
    # Test case 2
    solution2 = Task197(10.0, 5.0, -7.5)
    print("\\nTest case 2:")
    for _ in range(3):
        point = solution2.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
    
    # Test case 3
    solution3 = Task197(0.01, 0.0, 0.0)
    print("\\nTest case 3:")
    for _ in range(3):
        point = solution3.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
    
    # Test case 4
    solution4 = Task197(100.0, -50.0, 50.0)
    print("\\nTest case 4:")
    for _ in range(3):
        point = solution4.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
    
    # Test case 5
    solution5 = Task197(5.5, 3.3, -2.2)
    print("\\nTest case 5:")
    for _ in range(3):
        point = solution5.randPoint()
        print(f"[{point[0]:.5f}, {point[1]:.5f}]")
