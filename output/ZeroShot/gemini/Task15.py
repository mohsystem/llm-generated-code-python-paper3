def build_tower(n_floors):
    """
    Builds a pyramid-shaped tower as a list of strings.

    Args:
        n_floors: The number of floors in the tower. Must be a positive integer.

    Returns:
        A list of strings representing the tower. Returns an empty list for n_floors <= 0.
    """
    if n_floors <= 0:
        return []
    
    tower = []
    width = 2 * n_floors - 1
    for i in range(n_floors):
        stars = '*' * (2 * i + 1)
        spaces = ' ' * ((width - len(stars)) // 2)
        tower.append(spaces + stars + spaces)
    
    return tower

def print_tower(tower):
    """Helper function to print a tower in the specified format."""
    if not tower:
        print("[]")
        return
    print("[")
    for i, floor in enumerate(tower):
        comma = "," if i < len(tower) - 1 else ""
        print(f'  "{floor}"{comma}')
    print("]")

if __name__ == "__main__":
    test_cases = [1, 3, 6, 0, -2]
    
    for n in test_cases:
        print(f"Tower with {n} floors:")
        tower_result = build_tower(n)
        print_tower(tower_result)
        print()