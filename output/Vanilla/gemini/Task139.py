import math

def calculate_area(radius):
    """
    Calculates the area of a circle.

    :param radius: The radius of the circle.
    :return: The area of the circle.
    """
    return math.pi * radius * radius

if __name__ == "__main__":
    # 5 Test Cases
    test_radii = [1.0, 5.0, 10.0, 0.0, 7.5]
    print("Python Results:")
    for radius in test_radii:
        print(f"Radius: {radius}, Area: {calculate_area(radius)}")