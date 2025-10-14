import math

def cube_diagonal(volume):
  """
  Calculates the length of a cube's main diagonal from its volume.

  :param volume: The volume of the cube.
  :return: The length of the main diagonal, rounded to two decimal places.
  """
  # Side of the cube = cube root of the volume
  side = volume ** (1/3)
  
  # Main diagonal = side * sqrt(3)
  diagonal = side * math.sqrt(3)
  
  # Round the result to two decimal places
  return round(diagonal, 2)

if __name__ == '__main__':
    # Test cases
    print(cube_diagonal(8))
    print(cube_diagonal(343))
    print(cube_diagonal(1157.625))
    print(cube_diagonal(1))
    print(cube_diagonal(1000))