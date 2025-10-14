def nb_year(p0, percent, aug, p):
    """
    Calculates the number of years required for a population to reach a target.

    Args:
        p0 (int): The initial population.
        percent (float): The annual percentage increase.
        aug (int): The number of inhabitants coming or leaving each year.
        p (int): The target population to surpass.

    Returns:
        int: The number of full years needed.
    """
    years = 0
    current_population = p0
    percent_decimal = percent / 100.0

    while current_population < p:
        # Calculate the population for the next year and truncate to the nearest whole number.
        current_population = int(current_population + current_population * percent_decimal + aug)
        years += 1
    
    return years

if __name__ == "__main__":
    # Test Case 1: From example
    print(nb_year(1500, 5, 100, 5000))
    # Test Case 2: From example
    print(nb_year(1500000, 2.5, 10000, 2000000))
    # Test Case 3: Initial prompt example
    print(nb_year(1000, 2, 50, 1200))
    # Test Case 4: Initial population is already at or above target
    print(nb_year(1200, 2, 50, 1200))
    # Test Case 5: Small growth
    print(nb_year(1000, 0.5, 2, 1010))