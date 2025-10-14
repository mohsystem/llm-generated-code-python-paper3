def find_nb(m):
    """
    Finds the number of cubes n such that the sum of the first n cubes
    equals the given total volume m.
    The sum is n^3 + (n-1)^3 + ... + 1^3.

    :param m: The total volume of the building.
    :return: The number of cubes n, or -1 if no such n exists.
    """
    n = 0
    total_volume = 0
    while total_volume < m:
        n += 1
        total_volume += n**3
    
    return n if total_volume == m else -1

if __name__ == '__main__':
    # Test cases
    print(find_nb(1071225))
    print(find_nb(91716553919377))
    print(find_nb(4183059834009))
    print(find_nb(1))
    print(find_nb(24723578342962))