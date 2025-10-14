import math

def cubeDiagonal(volume):
    """
    Calculates the length of a cube's main diagonal from its volume.

    :param volume: The volume of the cube. Must be a positive number.
    :return: The length of the main diagonal, rounded to two decimal places.
             Returns 0.0 for non-positive volume.
    """
    # Secure coding: Validate input to ensure it's within the valid domain.
    if volume <= 0:
        return 0.0

    # V = s^3  =>  s = V^(1/3)
    # Using volume**(1/3) for compatibility with older Python versions
    side = volume**(1/3)

    # Diagonal d = s * sqrt(3)
    diagonal = side * math.sqrt(3)

    # Round the result to two decimal places.
    return round(diagonal, 2)

if __name__ == "__main__":
    # 5 test cases
    print(f"{cubeDiagonal(8):.2f}")
    print(f"{cubeDiagonal(343):.2f}")
    print(f"{cubeDiagonal(1157.625):.2f}")
    print(f"{cubeDiagonal(1):.2f}")
    print(f"{cubeDiagonal(27):.2f}")