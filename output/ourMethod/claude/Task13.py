
from typing import List

def is_valid_walk(walk: List[str]) -> bool:
    """\n    Determines if a walk takes exactly 10 minutes and returns to starting point.\n    \n    Args:\n        walk: List of direction strings ('n', 's', 'e', 'w')\n    \n    Returns:\n        bool: True if walk is valid, False otherwise\n    """
    # Validate input: check for None
    if walk is None:
        return False
    
    # Check if walk is exactly 10 minutes
    if len(walk) != 10:
        return False
    
    # Track position
    x = 0
    y = 0
    
    # Valid directions set for validation
    valid_directions = {'n', 's', 'e', 'w'}
    
    # Process each direction
    for direction in walk:
        # Validate direction type and value
        if not isinstance(direction, str) or direction not in valid_directions:
            return False
        
        if direction == 'n':
            y += 1
        elif direction == 's':
            y -= 1
        elif direction == 'e':
            x += 1
        elif direction == 'w':
            x -= 1
    
    # Check if we're back at starting point\n    return x == 0 and y == 0\n\n\nif __name__ == "__main__":\n    # Test case 1: Valid 10-minute walk returning to start\n    test1 = ['n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's']\n    print(f"Test 1: {is_valid_walk(test1)}")  # True\n    \n    # Test case 2: Valid 10-minute walk returning to start\n    test2 = ['w', 'e', 'w', 'e', 'w', 'e', 'w', 'e', 'w', 'e']\n    print(f"Test 2: {is_valid_walk(test2)}")  # True\n    \n    # Test case 3: 10 minutes but doesn't return to start
    test3 = ['n', 'n', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print(f"Test 3: {is_valid_walk(test3)}")  # False
    
    # Test case 4: Returns to start but not 10 minutes
    test4 = ['n', 's', 'w', 'e']
    print(f"Test 4: {is_valid_walk(test4)}")  # False
    
    # Test case 5: Valid complex path
    test5 = ['w', 'w', 'w', 'e', 'n', 'n', 's', 's', 'e', 'e']
    print(f"Test 5: {is_valid_walk(test5)}")  # True
