import math

def nb_year(p0: int, percent: float, aug: int, p: int) -> int:
    """
    Calculates the number of years required for a population to reach a target.

    Args:
        p0: Initial population. Must be > 0.
        percent: Annual percentage growth. Must be >= 0.
        aug: Annual net change in inhabitants (can be positive or negative).
        p: Target population. Must be > 0.

    Returns:
        The number of full years to reach or exceed the target population.
    """
    years = 0
    current_population = p0
    percent_decimal = percent / 100.0

    while current_population < p:
        current_population = math.floor(current_population * (1 + percent_decimal) + aug)
        years += 1
    
    return years

if __name__ == '__main__':
    # Test Case 1: Standard growth
    print(f"Test Case 1: Expected 15, Got {nb_year(1500, 5, 100, 5000)}")

    # Test Case 2: Large numbers
    print(f"Test Case 2: Expected 10, Got {nb_year(1500000, 2.5, 10000, 2000000)}")

    # Test Case 3: Example from prompt
    print(f"Test Case 3: Expected 3, Got {nb_year(1000, 2, 50, 1200)}")

    # Test Case 4: Initial population already meets target
    print(f"Test Case 4: Expected 0, Got {nb_year(1200, 2, 50, 1200)}")

    # Test Case 5: Slow growth
    print(f"Test Case 5: Expected 4, Got {nb_year(1000, 0.5, 20, 1100)}")