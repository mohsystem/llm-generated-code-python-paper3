import math
from typing import List

def calculate_circle_area(radius: float) -> float:
    """
    Calculates the area of a circle given its radius.
    The area is calculated as PI * radius^2.

    Args:
        radius: The radius of the circle. Must be a non-negative number.

    Returns:
        The area of the circle.

    Raises:
        ValueError: if the radius is negative.
    """
    if radius < 0:
        raise ValueError("Radius cannot be negative.")
    return math.pi * radius * radius

def main():
    """Main function to run test cases."""
    test_radii: List[float] = [0.0, 1.0, 5.5, 10.0, -2.0]
    
    for i, r in enumerate(test_radii):
        try:
            area = calculate_circle_area(r)
            print(f"Test Case {i+1}: Radius = {r:.2f}, Area = {area:.4f}")
        except ValueError as e:
            print(f"Test Case {i+1}: Radius = {r:.2f}, Error: {e}")

if __name__ == "__main__":
    main()