
def nb_year(p0, percent, aug, p):
    # Input validation to prevent security issues
    if p0 <= 0 or p <= 0 or percent < 0:
        raise ValueError("Invalid input parameters")
    
    # Type validation
    if not isinstance(p0, int) or not isinstance(p, int) or not isinstance(aug, int):
        raise TypeError("p0, p, and aug must be integers")
    
    if not isinstance(percent, (int, float)):
        raise TypeError("percent must be a number")
    
    years = 0
    current_population = p0
    
    # Convert percent to decimal (e.g., 2 -> 0.02)
    percent_decimal = percent / 100.0
    
    # Calculate years needed with overflow protection
    max_iterations = 10000
    while current_population < p:
        # Prevent infinite loop
        if years >= max_iterations:
            raise RuntimeError("Calculation exceeded maximum iterations")
        
        # Calculate new population with integer conversion (floor)
        new_population = int(current_population + current_population * percent_decimal + aug)
        
        # Check for reasonable values
        if new_population < 0 or new_population > 10**15:
            raise OverflowError("Population overflow occurred")
        
        current_population = new_population
        years += 1
    
    return years


if __name__ == "__main__":
    # Test case 1
    print(f"Test 1: {nb_year(1000, 2, 50, 1200)} (Expected: 3)")
    
    # Test case 2
    print(f"Test 2: {nb_year(1500, 5, 100, 5000)} (Expected: 15)")
    
    # Test case 3
    print(f"Test 3: {nb_year(1500000, 2.5, 10000, 2000000)} (Expected: 10)")
    
    # Test case 4
    print(f"Test 4: {nb_year(1000, 0, 50, 1200)} (Expected: 4)")
    
    # Test case 5
    print(f"Test 5: {nb_year(1500, 10, 200, 10000)} (Expected: 14)")
