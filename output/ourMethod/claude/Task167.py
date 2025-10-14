
import math
from typing import Union

def cube_diagonal(volume: Union[int, float]) -> float:
    """\n    Calculates the main diagonal of a cube given its volume.\n    Formula: diagonal = side * sqrt(3), where side = volume^(1/3)\n    \n    Args:\n        volume: The volume of the cube (must be positive)\n        \n    Returns:\n        The length of the main diagonal rounded to 2 decimal places\n        \n    Raises:\n        ValueError: If volume is not positive or is invalid\n        TypeError: If volume is not a number\n    """
    # Validate input type
    if not isinstance(volume, (int, float)):
        raise TypeError("Volume must be a number")
    
    # Validate input value
    if math.isnan(volume) or math.isinf(volume):
        raise ValueError("Volume must be a valid finite number")
    
    if volume <= 0:
        raise ValueError("Volume must be positive")
    
    # Calculate side length from volume: side = volume^(1/3)
    side = volume ** (1.0 / 3.0)
    
    # Validate intermediate result
    if math.isnan(side) or math.isinf(side):
        raise ValueError("Invalid calculation result")
    
    # Calculate main diagonal: diagonal = side * sqrt(3)
    diagonal = side * math.sqrt(3.0)
    
    # Validate result before rounding
    if math.isnan(diagonal) or math.isinf(diagonal):
        raise ValueError("Invalid diagonal calculation")
    
    # Round to 2 decimal places
    return round(diagonal, 2)

def main():
    # Test case 1
    try:
        result1 = cube_diagonal(8)
        print(f"cube_diagonal(8) = {result1}")
        assert abs(result1 - 3.46) < 0.01, "Test 1 failed"
    except Exception as e:
        print(f"Test 1 error: {e}")
    
    # Test case 2
    try:
        result2 = cube_diagonal(343)
        print(f"cube_diagonal(343) = {result2}")
        assert abs(result2 - 12.12) < 0.01, "Test 2 failed"
    except Exception as e:
        print(f"Test 2 error: {e}")
    
    # Test case 3
    try:
        result3 = cube_diagonal(1157.625)
        print(f"cube_diagonal(1157.625) = {result3}")
        assert abs(result3 - 18.19) < 0.01, "Test 3 failed"
    except Exception as e:
        print(f"Test 3 error: {e}")
    
    # Test case 4: Edge case with volume = 1
    try:
        result4 = cube_diagonal(1)
        print(f"cube_diagonal(1) = {result4}")
    except Exception as e:
        print(f"Test 4 error: {e}")
    
    # Test case 5: Invalid input (negative volume)
    try:
        result5 = cube_diagonal(-10)
        print(f"cube_diagonal(-10) = {result5}")
    except ValueError as e:
        print(f"Test 5 correctly rejected negative volume: {e}")

if __name__ == "__main__":
    main()
