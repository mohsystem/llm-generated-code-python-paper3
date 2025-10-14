def build_tower(n_floors):
    """
    Builds a pyramid-shaped tower as a list of strings.

    :param n_floors: The number of floors in the tower (must be a positive integer).
    :return: A list of strings representing the tower. Returns an empty list if n_floors is not positive.
    """
    if n_floors <= 0:
        return []
    
    tower = []
    # The width of the tower is determined by the last floor
    width = 2 * n_floors - 1
    
    for i in range(1, n_floors + 1):
        num_stars = 2 * i - 1
        num_spaces = n_floors - i
        
        spaces = ' ' * num_spaces
        stars = '*' * num_stars
        
        tower.append(spaces + stars + spaces)
        
    return tower

if __name__ == '__main__':
    test_cases = [1, 3, 6, 0, 5]
    for i, n in enumerate(test_cases):
        print(f"Test Case {i + 1}: n_floors = {n}")
        tower = build_tower(n)
        if not tower:
            print("[]")
        else:
            print("[")
            for floor in tower:
                print(f'  "{floor}"')
            print("]")
        print("--------------------")