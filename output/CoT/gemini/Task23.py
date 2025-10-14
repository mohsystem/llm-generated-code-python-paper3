def find_nb(m):
    """
    Finds the number of cubes n such that the sum of the first n cubes equals m.
    """
    total_volume = 0
    n = 0
    while total_volume < m:
        n += 1
        total_volume += n**3
    
    return n if total_volume == m else -1

if __name__ == '__main__':
    print("Python Test Cases:")
    # Test Case 1: Example from description
    print(f"find_nb(1071225) -> Expected: 45, Got: {find_nb(1071225)}")
    # Test Case 2: Example from description, no solution
    print(f"find_nb(91716553919377) -> Expected: -1, Got: {find_nb(91716553919377)}")
    # Test Case 3: A large number with a solution
    print(f"find_nb(4183059834009) -> Expected: 2022, Got: {find_nb(4183059834009)}")
    # Test Case 4: Smallest possible input with a solution
    print(f"find_nb(1) -> Expected: 1, Got: {find_nb(1)}")
    # Test Case 5: Another large number with a solution
    print(f"find_nb(135440716410000) -> Expected: 4824, Got: {find_nb(135440716410000)}")