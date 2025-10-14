
import math

def cube_diagonal(volume):
    # Calculate side length from volume: side = cube_root(volume)
    side = volume ** (1/3)
    
    # Calculate main diagonal: diagonal = side * sqrt(3)
    diagonal = side * math.sqrt(3)
    
    # Round to 2 decimal places
    return round(diagonal, 2)

# Test cases
if __name__ == "__main__":
    print(cube_diagonal(8))           # Expected: 3.46
    print(cube_diagonal(343))         # Expected: 12.12
    print(cube_diagonal(1157.625))    # Expected: 18.19
    print(cube_diagonal(1))           # Expected: 1.73
    print(cube_diagonal(27))          # Expected: 5.20
