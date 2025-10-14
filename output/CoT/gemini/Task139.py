import math

def calculate_circle_area(radius):
    """
    Calculates the area of a circle.

    Args:
        radius: The radius of the circle. Must be a non-negative number.

    Returns:
        The area of the circle, or -1.0 if the radius is negative.
    """
    # Security: Ensure the radius is not negative.
    if not isinstance(radius, (int, float)) or radius < 0:
        return -1.0  # Return an error indicator for invalid input.
    
    return math.pi * (radius ** 2)

def main():
    # 5 Test Cases
    test_radii = [10.0, 5.5, 0.0, 1.0, -7.0]

    print("Python Test Cases:")
    for radius in test_radii:
        area = calculate_circle_area(radius)
        if area == -1.0:
            print(f"Radius: {radius} -> Error: Radius cannot be negative.")
        else:
            print(f"Radius: {radius:.2f} -> Area: {area:.2f}")

if __name__ == "__main__":
    main()