
def is_valid_walk(walk):
    if len(walk) != 10:
        return False
    
    x, y = 0, 0
    
    for direction in walk:
        if direction == 'n':
            y += 1
        elif direction == 's':
            y -= 1
        elif direction == 'e':
            x += 1
        elif direction == 'w':
            x -= 1
    
    return x == 0 and y == 0

if __name__ == "__main__":
    # Test case 1: Valid walk
    test1 = ['n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print(f"Test 1: {is_valid_walk(test1)}")  # Expected: True
    
    # Test case 2: Valid walk with all directions
    test2 = ['n', 's', 'e', 'w', 'n', 's', 'e', 'w', 'n', 's']
    print(f"Test 2: {is_valid_walk(test2)}")  # Expected: True
    
    # Test case 3: Too short
    test3 = ['n', 's', 'n', 's', 'n']
    print(f"Test 3: {is_valid_walk(test3)}")  # Expected: False
    
