from typing import List

def is_valid_walk(walk: List[str]) -> bool:
    """
    Determines if a given walk is valid.
    A valid walk takes exactly 10 minutes and returns to the starting point.

    Args:
        walk: A list of single-character strings representing directions ('n', 's', 'e', 'w').
    
    Returns:
        True if the walk is valid, False otherwise.
    """
    if len(walk) != 10:
        return False
    
    x = 0  # East-West displacement
    y = 0  # North-South displacement
    
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

if __name__ == '__main__':
    # Test Case 1: Valid walk
    walk1 = ['n','s','n','s','n','s','n','s','n','s']
    print(f"Test 1: {is_valid_walk(walk1)}")

    # Test Case 2: Too long
    walk2 = ['w','e','w','e','w','e','w','e','w','e','w','e']
    print(f"Test 2: {is_valid_walk(walk2)}")

    # Test Case 3: Too short
    walk3 = ['w']
    print(f"Test 3: {is_valid_walk(walk3)}")

    # Test Case 4: Correct length, but does not return to start
    walk4 = ['n','n','n','s','n','s','n','s','n','s']
    print(f"Test 4: {is_valid_walk(walk4)}")
    
    # Test Case 5: Valid walk, different order
    walk5 = ['e', 'w', 'e', 'w', 'n', 's', 'n', 's', 'e', 'w']
    print(f"Test 5: {is_valid_walk(walk5)}")