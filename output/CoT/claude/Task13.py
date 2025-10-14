
def is_valid_walk(walk):
    # Check if walk is None to prevent errors
    if walk is None:
        return False
    
    # Check if the walk takes exactly 10 minutes
    if len(walk) != 10:
        return False
    
    # Track position on grid
    x = 0
    y = 0
    
    # Process each direction
    for direction in walk:
        # Validate that only allowed directions are present
        if direction not in ['n', 's', 'e', 'w']:
            return False
        
        # Update position based on direction
        if direction == 'n':
            y += 1
        elif direction == 's':
            y -= 1
        elif direction == 'e':
            x += 1
        elif direction == 'w':
            x -= 1
    
    # Check if we returned to starting point
    return x == 0 and y == 0


if __name__ == "__main__":
    # Test case 1: Valid 10-minute walk returning to start
    test1 = ['n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print(f"Test 1: {is_valid_walk(test1)}")  # Expected: True
    
    # Test case 2: Valid 10-minute walk with all directions
    test2 = ['n', 's', 'e', 'w', 'n', 's', 'e', 'w', 'n', 's']
    print(f"Test 2: {is_valid_walk(test2)}")  # Expected: True
    
    # Test case 3: Too short walk
    test3 = ['n', 's', 'e', 'w']
    print(f"Test 3: {is_valid_walk(test3)}")  # Expected: False
    
    # Test case 4: Correct length but doesn't return to start\n    test4 = ['n', 'n', 'n', 's', 's', 's', 'e', 'w', 'n', 's']\n    print(f"Test 4: {is_valid_walk(test4)}")  # Expected: False\n    \n    # Test case 5: Too long walk\n    test5 = ['n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print(f"Test 5: {is_valid_walk(test5)}")  # Expected: False
