
MAX_FLOORS = 1000  # Prevent excessive memory usage

def build_tower(n_floors):
    """\n    Build a pyramid-shaped tower as a list of strings.\n    \n    Args:\n        n_floors: Positive integer representing number of floors\n        \n    Returns:\n        List of strings representing the tower\n    """
    # Input validation
    if not isinstance(n_floors, int):
        raise TypeError("Number of floors must be an integer")
    
    if n_floors <= 0:
        return []
    
    if n_floors > MAX_FLOORS:
        raise ValueError(f"Number of floors exceeds maximum allowed: {MAX_FLOORS}")
    
    tower = []
    width = 2 * n_floors - 1
    
    for i in range(n_floors):
        stars = 2 * i + 1
        spaces = (width - stars) // 2
        floor = ' ' * spaces + '*' * stars + ' ' * spaces
        tower.append(floor)
    
    return tower


if __name__ == "__main__":
    # Test case 1: 3 floors
    print("Test 1 - 3 floors:")
    result1 = build_tower(3)
    for floor in result1:
        print(f'"{floor}"')
    
    # Test case 2: 6 floors
    print("\\nTest 2 - 6 floors:")
    result2 = build_tower(6)
    for floor in result2:
        print(f'"{floor}"')
    
    # Test case 3: 1 floor
    print("\\nTest 3 - 1 floor:")
    result3 = build_tower(1)
    for floor in result3:
        print(f'"{floor}"')
    
    # Test case 4: 0 floors (edge case)
    print("\\nTest 4 - 0 floors:")
    result4 = build_tower(0)
    print(f"Empty array, length: {len(result4)}")
    
    # Test case 5: 10 floors
    print("\\nTest 5 - 10 floors:")
    result5 = build_tower(10)
    for floor in result5:
        print(f'"{floor}"')
