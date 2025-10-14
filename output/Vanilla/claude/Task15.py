
def build_tower(n_floors):
    tower = []
    max_width = 2 * n_floors - 1
    
    for i in range(n_floors):
        stars = 2 * i + 1
        spaces = (max_width - stars) // 2
        floor = " " * spaces + "*" * stars + " " * spaces
        tower.append(floor)
    
    return tower


if __name__ == "__main__":
    # Test case 1
    print("Test case 1: 3 floors")
    tower1 = build_tower(3)
    for floor in tower1:
        print(f'"{floor}"')
    print()
    
    # Test case 2
    print("Test case 2: 6 floors")
    tower2 = build_tower(6)
    for floor in tower2:
        print(f'"{floor}"')
    print()
    
    # Test case 3
    print("Test case 3: 1 floor")
    tower3 = build_tower(1)
    for floor in tower3:
        print(f'"{floor}"')
    print()
    
    # Test case 4
    print("Test case 4: 5 floors")
    tower4 = build_tower(5)
    for floor in tower4:
        print(f'"{floor}"')
    print()
    
    # Test case 5
    print("Test case 5: 10 floors")
    tower5 = build_tower(10)
    for floor in tower5:
        print(f'"{floor}"')
