import math

def cube_diagonal(volume):
    """
    Calculates the length of a cube's main diagonal from its volume.

    :param volume: The volume of the cube.
    :return: The length of the main diagonal, rounded to two decimal places.
    """
    if volume < 0:
        return 0.0  # Or raise an exception for invalid input
        
    # side = cube root of volume
    side = volume ** (1/3)
    
    # diagonal = side * sqrt(3)
    diagonal = side * math.sqrt(3)
    
    # Round to two decimal places
    return round(diagonal, 2)

# Main block with test cases
if __name__ == "__main__":
    print("Test Case 1: cube_diagonal(8)")
    print(f"Expected: 3.46")
    print(f"Actual: {cube_diagonal(8)}")
    print()

    print("Test Case 2: cube_diagonal(343)")
    print(f"Expected: 12.12")
    print(f"Actual: {cube_diagonal(343)}")
    print()

    print("Test Case 3: cube_diagonal(1157.625)")
    print(f"Expected: 18.19")
    print(f"Actual: {cube_diagonal(1157.625)}")
    print()

    print("Test Case 4: cube_diagonal(1)")
    print(f"Expected: 1.73")
    print(f"Actual: {cube_diagonal(1)}")
    print()

    print("Test Case 5: cube_diagonal(27)")
    print(f"Expected: 5.20")
    print(f"Actual: {cube_diagonal(27)}")
    print()