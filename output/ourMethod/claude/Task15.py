
from typing import List

def build_tower(n_floors: int) -> List[str]:
    """\n    Build a pyramid-shaped tower as a list of strings.\n    \n    Args:\n        n_floors: Positive integer representing the number of floors\n        \n    Returns:\n        List of strings representing each floor of the tower\n        \n    Raises:\n        ValueError: If n_floors is not a positive integer\n    """
    # Validate input
    if not isinstance(n_floors, int):
        raise TypeError("Number of floors must be an integer")
    if n_floors <= 0:
        raise ValueError("Number of floors must be positive")
    if n_floors > 10000:
        raise ValueError("Number of floors exceeds maximum allowed")
    
    tower = []
    max_width = 2 * n_floors - 1
    
    for i in range(n_floors):
        num_stars = 2 * i + 1
        num_spaces = (max_width - num_stars) // 2
        
        floor = ' ' * num_spaces + '*' * num_stars + ' ' * num_spaces
        tower.append(floor)
    
    return tower


if __name__ == "__main__":
    # Test case 1: 3 floors
    print("Test 1 - 3 floors:")
    tower1 = build_tower(3)
    for floor in tower1:
        print(f'"{floor}"')
    print()
    
    # Test case 2: 6 floors
    print("Test 2 - 6 floors:")
    tower2 = build_tower(6)
    for floor in tower2:
        print(f'"{floor}"')
    print()
    
    # Test case 3: 1 floor
    print("Test 3 - 1 floor:")
    tower3 = build_tower(1)
    for floor in tower3:
        print(f'"{floor}"')
    print()
    
    # Test case 4: 5 floors
    print("Test 4 - 5 floors:")
    tower4 = build_tower(5)
    for floor in tower4:
        print(f'"{floor}"')
    print()
    
    # Test case 5: 10 floors
    print("Test 5 - 10 floors:")
    tower5 = build_tower(10)
    for floor in tower5:
        print(f'"{floor}"')
