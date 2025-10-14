
def find_nb(m: int) -> int:
    """\n    Find n such that 1^3 + 2^3 + ... + n^3 = m\n    Returns n if found, -1 otherwise\n    """
    # Input validation
    if not isinstance(m, int):
        return -1
    if m < 0:
        return -1
    if m == 0:
        return 0
    
    n = 0
    total = 0
    
    # Iterate to find n such that sum of cubes equals m
    while total < m:
        n += 1
        # Prevent infinite loop with reasonable upper bound
        if n > 1000000:
            return -1
        cube = n * n * n
        total += cube
    
    return n if total == m else -1


if __name__ == "__main__":
    # Test cases
    print(f"Test 1: find_nb(1071225) = {find_nb(1071225)}")
    print(f"Test 2: find_nb(91716553919377) = {find_nb(91716553919377)}")
    print(f"Test 3: find_nb(4183059834009) = {find_nb(4183059834009)}")
    print(f"Test 4: find_nb(24723578342962) = {find_nb(24723578342962)}")
    print(f"Test 5: find_nb(135440716410000) = {find_nb(135440716410000)}")
