
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
    
    # Test case 4: Correct length but doesn't return to start\n    test4 = ['n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n']\n    print(f"Test 4: {is_valid_walk(test4)}")  # Expected: False\n    \n    # Test case 5: Too long\n    test5 = ['n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print(f"Test 5: {is_valid_walk(test5)}")  # Expected: False
