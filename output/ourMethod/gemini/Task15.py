from typing import List

def build_tower(n_floors: int) -> List[str]:
    """
    Builds a pyramid-shaped tower.

    :param n_floors: The number of floors in the tower (must be positive).
    :return: A list of strings representing the tower.
    """
    if n_floors <= 0:
        return []
    
    tower = []
    width = 2 * n_floors - 1
    for i in range(n_floors):
        stars = '*' * (2 * i + 1)
        tower.append(stars.center(width))
        
    return tower

if __name__ == '__main__':
    test_cases = [1, 3, 6, 0, -5]
    for floors in test_cases:
        print(f"Tower with {floors} floors:")
        tower = build_tower(floors)
        if not tower:
            print("[]")
        else:
            print("[")
            for floor in tower:
                print(f'  "{floor}"')
            print("]")
        print()