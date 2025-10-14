
import math
import sys

def calculate_circle_area(radius):
    """\n    Calculate the area of a circle given its radius.\n    \n    Args:\n        radius: The radius of the circle (float or int)\n    \n    Returns:\n        The area of the circle\n    \n    Raises:\n        ValueError: If radius is negative or invalid\n    """
    # Input validation
    if not isinstance(radius, (int, float)):
        raise TypeError("Radius must be a numeric value")
    
    if radius < 0:
        raise ValueError("Radius cannot be negative")
    
    if math.isnan(radius) or math.isinf(radius):
        raise ValueError("Invalid radius value")
    
    # Check for potential overflow
    if radius > math.sqrt(sys.float_info.max / math.pi):
        raise OverflowError("Radius too large, calculation would overflow")
    
    # Calculate area
    area = math.pi * radius * radius
    
    return area

def main():
    """Main function with test cases"""
    print("Test Case 1 - Radius: 5.0")
    print(f"Area: {calculate_circle_area(5.0)}")
    
    print("\\nTest Case 2 - Radius: 10.5")
    print(f"Area: {calculate_circle_area(10.5)}")
    
    print("\\nTest Case 3 - Radius: 0.0")
    print(f"Area: {calculate_circle_area(0.0)}")
    
    print("\\nTest Case 4 - Radius: 1.0")
    print(f"Area: {calculate_circle_area(1.0)}")
    
    print("\\nTest Case 5 - Radius: 7.5")
    print(f"Area: {calculate_circle_area(7.5)}")
    
    # Test error case
    try:
        print("\\nTest Case 6 - Radius: -5.0 (Error case)")
        print(f"Area: {calculate_circle_area(-5.0)}")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
