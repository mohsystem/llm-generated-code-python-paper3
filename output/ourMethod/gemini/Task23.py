def find_nb(m: int) -> int:
    """
    Find the number of cubes n such that the sum of the first n cubes equals m.
    """
    n = 0
    remaining_volume = m
    while remaining_volume > 0:
        n += 1
        cube_volume = n * n * n
        remaining_volume -= cube_volume
    
    if remaining_volume == 0:
        return n
    else:
        return -1

if __name__ == '__main__':
    # Test cases
    test_cases = [
        (1071225, 45),
        (91716553919377, -1),
        (4183059834009, 2022),
        (24723578342962, -1),
        (1, 1)
    ]

    for m, expected in test_cases:
        result = find_nb(m)
        print(f"find_nb({m}) -> {result} (Expected: {expected})")