import math

def calculate_circle_area(radius):
    """
    Calculates the area of a circle securely.

    Args:
        radius (float or int): The radius of the circle. Must be non-negative.

    Returns:
        float: The area of the circle.

    Raises:
        TypeError: If the radius is not a number.
        ValueError: If the radius is negative.
    """
    if not isinstance(radius, (int, float)):
        raise TypeError("Radius must be a number.")
    if radius < 0:
        raise ValueError("Radius cannot be negative.")
    return math.pi * (radius ** 2)

def main():
    """ Main function with test cases. """
    test_radii = [0.0, 1.0, 5.5, 10.0, -2.0]
    print("Running Python test cases:")

    for radius in test_radii:
        try:
            area = calculate_circle_area(radius)
            print(f"Radius: {radius:.2f}, Area: {area:.2f}")
        except (ValueError, TypeError) as e:
            print(f"Radius: {radius:.2f}, Error: {e}")

if __name__ == "__main__":
    main()