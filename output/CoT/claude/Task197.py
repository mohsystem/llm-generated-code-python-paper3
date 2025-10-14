
import random
import math

class Task197:
    def __init__(self, radius, x_center, y_center):
        if radius <= 0:
            raise ValueError("Radius must be positive")
        self.radius = radius
        self.x_center = x_center
        self.y_center = y_center
    
    def randPoint(self):
        angle = random.uniform(0, 2 * math.pi)
        r = math.sqrt(random.uniform(0, 1)) * self.radius
        
        x = self.x_center + r * math.cos(angle)
        y = self.y_center + r * math.sin(angle)
        
        return [x, y]

if __name__ == "__main__":
    solution1 = Task197(1.0, 0.0, 0.0)
    print("Test 1:", solution1.randPoint())
    print("Test 2:", solution1.randPoint())
    print("Test 3:", solution1.randPoint())
    
    solution2 = Task197(5.0, 2.0, 3.0)
    print("Test 4:", solution2.randPoint())
    print("Test 5:", solution2.randPoint())
