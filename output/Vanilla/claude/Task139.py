
import math

def calculate_area(radius):
    return math.pi * radius * radius

if __name__ == "__main__":
    # Test cases
    print("Test Case 1 - Radius: 5.0")
    print(f"Area: {calculate_area(5.0)}")
    print()
    
    print("Test Case 2 - Radius: 10.5")
    print(f"Area: {calculate_area(10.5)}")
    print()
    
    print("Test Case 3 - Radius: 1.0")
    print(f"Area: {calculate_area(1.0)}")
    print()
    
    print("Test Case 4 - Radius: 7.25")
    print(f"Area: {calculate_area(7.25)}")
    print()
    
    print("Test Case 5 - Radius: 15.8")
    print(f"Area: {calculate_area(15.8)}")
