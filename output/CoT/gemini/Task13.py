def is_valid_walk(walk):
    """
    Determines if a given walk is valid.
    A valid walk takes exactly 10 minutes and returns to the starting point.
    """
    # 1. The walk must take exactly 10 minutes.
    if len(walk) != 10:
        return False

    # 2. The walk must return to the starting point.
    # This means the number of 'n' moves must equal 's' moves,
    # and the number of 'e' moves must equal 'w' moves.
    return walk.count('n') == walk.count('s') and walk.count('e') == walk.count('w')

# main method with test cases
if __name__ == '__main__':
    test_cases = [
        (['n','s','n','s','n','s','n','s','n','s'], True),
        (['w','e','w','e','w','e','w','e','w','e'], True),
        (['w'], False),
        (['n','n','n','s','n','s','n','s','n','s'], False),
        (['e','e','e','e','w','w','w','w','w','w'], False)
    ]

    for i, (walk_input, expected) in enumerate(test_cases):
        result = is_valid_walk(walk_input)
        print(f"Test Case {i + 1}: {walk_input}")
        print(f"Result: {result}")
        # print(f"Expected: {expected}")
        # print(f"Pass: {result == expected}")
        print()