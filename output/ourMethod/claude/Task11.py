
def nb_year(p0: int, percent: float, aug: int, p: int) -> int:
    """\n    Calculate the number of years needed for population to reach target.\n    \n    Args:\n        p0: Initial population (positive integer)\n        percent: Annual growth percentage (positive or zero)\n        aug: Annual inhabitants increase/decrease (integer)\n        p: Target population (positive integer)\n    \n    Returns:\n        Number of years needed\n    """
    # Validate inputs
    if not isinstance(p0, int) or not isinstance(p, int):
        raise TypeError("p0 and p must be integers")
    
    if p0 <= 0 or p <= 0:
        raise ValueError("p0 and p must be positive integers")
    
    if not isinstance(percent, (int, float)):
        raise TypeError("percent must be a number")
    
    if percent < 0.0:
        raise ValueError("percent must be positive or zero")
    
    if not isinstance(aug, int):
        raise TypeError("aug must be an integer")
    
    # Convert percent to decimal
    percent_decimal = percent / 100.0
    
    years = 0
    current_population = p0
    
    # Calculate years needed
    while current_population < p:
        # Calculate next year population: current + (current * percent) + aug
        # Convert to int to floor the result (no fractions of people)
        current_population = int(current_population + current_population * percent_decimal + aug)
        years += 1
        
        # Safety check to prevent infinite loop
        if years > 1000000:
            raise ArithmeticError("Calculation exceeded maximum iterations")
    
    return years


if __name__ == "__main__":
    # Test case 1
    print(f"Test 1: {nb_year(1000, 2, 50, 1200)} (expected: 3)")
    
    # Test case 2
    print(f"Test 2: {nb_year(1500, 5, 100, 5000)} (expected: 15)")
    
    # Test case 3
    print(f"Test 3: {nb_year(1500000, 2.5, 10000, 2000000)} (expected: 10)")
    
    # Test case 4
    print(f"Test 4: {nb_year(1000, 0, 50, 1200)} (expected: 4)")
    
    # Test case 5
    print(f"Test 5: {nb_year(1000, 2, 0, 1200)} (expected: 10)")
