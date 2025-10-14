import math

def cube_diagonal(volume: float) -> float:
    """
    Calculates the length of a cube's main diagonal given its volume.

    :param volume: The volume of the cube. Must be a positive number.
    :return: The length of the main diagonal, rounded to two decimal places.
    :raises ValueError: if the volume is not a positive number.
    """
    if volume <= 0:
        raise ValueError("Volume must be a positive number.")
    
    side = math.cbrt(volume)
    diagonal = side * math.sqrt(3)
    
    return round(diagonal, 2)

if __name__ == "__main__":
    # Test Case 1
    print(cube_diagonal(8))

    # Test Case 2
    print(cube_diagonal(343))

    # Test Case 3
    print(cube_diagonal(1157.625))
    
    # Test Case 4: Unit cube
    print(cube_diagonal(1))

    # Test Case 5: Invalid input
    try:
        print(cube_diagonal(-1))
    except ValueError as e:
        print(e)