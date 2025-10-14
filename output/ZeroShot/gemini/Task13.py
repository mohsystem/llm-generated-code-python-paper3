def is_valid_walk(walk):
    """
    Checks if a given walk is valid.
    A valid walk takes exactly 10 minutes (10 steps) and returns to the starting point.

    Args:
        walk: A list of characters representing directions ('n', 's', 'e', 'w').

    Returns:
        True if the walk is valid, False otherwise.
    """
    # A more idiomatic and concise Python solution.
    # Check if the walk is 10 minutes long and if the number of north moves
    # equals south moves, and east moves equals west moves.
    if len(walk) == 10 and walk.count('n') == walk.count('s') and walk.count('e') == walk.count('w'):
        return True
    return False

# Alternative implementation similar to other languages
# def is_valid_walk(walk):
#     if len(walk) != 10:
#         return False
#
#     x, y = 0, 0
#     for direction in walk:
#         if direction == 'n':
#             y += 1
#         elif direction == 's':
#             y -= 1
#         elif direction == 'e':
#             x += 1
#         elif direction == 'w':
#             x -= 1
#
#     return x == 0 and y == 0

if __name__ == '__main__':
    # Test Case 1: Valid walk
    walk1 = ['n', 's', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print(f"Test Case 1: {is_valid_walk(walk1)}")  # Expected: True

    # Test Case 2: Too long walk
    walk2 = ['w', 'e', 'w', 'e', 'w', 'e', 'w', 'e', 'w', 'e', 'w', 'e']
    print(f"Test Case 2: {is_valid_walk(walk2)}")  # Expected: False

    # Test Case 3: Too short walk
    walk3 = ['w']
    print(f"Test Case 3: {is_valid_walk(walk3)}")  # Expected: False

    # Test Case 4: Correct length, but does not return to start
    walk4 = ['n', 'n', 'n', 's', 'n', 's', 'n', 's', 'n', 's']
    print(f"Test Case 4: {is_valid_walk(walk4)}")  # Expected: False

    # Test Case 5: Valid walk with mixed directions
    walk5 = ['e', 'w', 'e', 'w', 'n', 's', 'n', 's', 'e', 'w']
    print(f"Test Case 5: {is_valid_walk(walk5)}")  # Expected: True