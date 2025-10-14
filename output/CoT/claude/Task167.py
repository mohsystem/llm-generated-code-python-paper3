
import math

def cube_diagonal(volume):
    # Input validation
    if not isinstance(volume, (int, float)):
        raise TypeError("Volume must be a number")
    
    if volume <= 0 or math.isnan(volume) or math.isinf(volume):
        raise ValueError("Volume must be a positive finite number")
    
    # Calculate side length from volume
    side = volume ** (1/3)
    
    # Calculate main diagonal: side * sqrt(3)
    diagonal = side * math.sqrt(3)
    
    # Round to 2 decimal places
    return round(diagonal, 2)

# Test cases
if __name__ == "__main__":
    print("Test 1:", cube_diagonal(8))           # Expected: 3.46
    print("Test 2:", cube_diagonal(343))         # Expected: 12.12
    print("Test 3:", cube_diagonal(1157.625))    # Expected: 18.19
    print("Test 4:", cube_diagonal(1))           # Expected: 1.73
    print("Test 5:", cube_diagonal(27))          # Expected: 5.2
