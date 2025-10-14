
import math

def calculate_circle_area(radius):
    if radius < 0:
        raise ValueError("Radius cannot be negative")
    return math.pi * radius * radius

def main():
    # Test cases
    print("Test Case 1 - Radius: 5")
    print(f"Area: {calculate_circle_area(5)}")
    
    print("\\nTest Case 2 - Radius: 10.5")
    print(f"Area: {calculate_circle_area(10.5)}")
    
    print("\\nTest Case 3 - Radius: 0")
    print(f"Area: {calculate_circle_area(0)}")
    
    print("\\nTest Case 4 - Radius: 1")
    print(f"Area: {calculate_circle_area(1)}")
    
    print("\\nTest Case 5 - Radius: 7.5")
    print(f"Area: {calculate_circle_area(7.5)}")
    
    # Uncomment to test negative radius
    # print("\\nTest Case 6 - Radius: -5")
    # print(f"Area: {calculate_circle_area(-5)}")

if __name__ == "__main__":
    main()
