
import math
from typing import Union

PI = 3.14159265358979323846
MAX_RADIUS = 1e308
MIN_RADIUS = 0.0

def calculate_circle_area(radius: Union[int, float]) -> float:
    """\n    Calculate the area of a circle given its radius.\n    \n    Args:\n        radius: The radius of the circle (must be non-negative)\n        \n    Returns:\n        The area of the circle\n        \n    Raises:\n        TypeError: If radius is not a number\n        ValueError: If radius is negative, NaN, or infinite\n    """
    # Validate input type
    if not isinstance(radius, (int, float)):
        raise TypeError("Invalid radius: must be a number")
    
    # Convert to float for consistent handling
    radius = float(radius)
    
    # Validate input: radius must be non-negative and within valid range
    if math.isnan(radius) or math.isinf(radius):
        raise ValueError("Invalid radius: must be a valid number")
    
    if radius < MIN_RADIUS:
        raise ValueError("Invalid radius: must be non-negative")
    
    if radius > MAX_RADIUS:
        raise ValueError("Invalid radius: exceeds maximum allowed value")
    
    # Calculate area: A = π * r²
    area = PI * radius * radius
    
    # Check for overflow
    if math.isinf(area):
        raise ArithmeticError("Area calculation resulted in overflow")
    
    return area

def main() -> None:
    """Run test cases for the circle area calculation."""
    
    # Test case 1: radius = 5.0
    try:
        result1 = calculate_circle_area(5.0)
        print(f"Test 1 - Radius: 5.0, Area: {result1}")
    except Exception as e:
        print(f"Test 1 failed: {e}", file=__import__('sys').stderr)

    # Test case 2: radius = 10.5
    try:
        result2 = calculate_circle_area(10.5)
        print(f"Test 2 - Radius: 10.5, Area: {result2}")
    except Exception as e:
        print(f"Test 2 failed: {e}", file=__import__('sys').stderr)

    # Test case 3: radius = 0.0 (edge case)
    try:
        result3 = calculate_circle_area(0.0)
        print(f"Test 3 - Radius: 0.0, Area: {result3}")
    except Exception as e:
        print(f"Test 3 failed: {e}", file=__import__('sys').stderr)

    # Test case 4: radius = 1.0
    try:
        result4 = calculate_circle_area(1.0)
        print(f"Test 4 - Radius: 1.0, Area: {result4}")
    except Exception as e:
        print(f"Test 4 failed: {e}", file=__import__('sys').stderr)

    # Test case 5: radius = -5.0 (invalid input)
    try:
        result5 = calculate_circle_area(-5.0)
        print(f"Test 5 - Radius: -5.0, Area: {result5}")
    except Exception as e:
        print(f"Test 5 failed (expected): {e}", file=__import__('sys').stderr)

if __name__ == "__main__":
    main()
