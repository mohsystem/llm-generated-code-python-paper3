def nb_year(p0, percent, aug, p):
    years = 0
    current_population = p0
    
    while current_population < p:
        current_population = current_population + current_population * (percent / 100.0) + aug
        # Truncate to an integer value at the end of each year
        current_population = int(current_population)
        years += 1
        
    return years

if __name__ == '__main__':
    # Test case 1
    print(nb_year(1500, 5, 100, 5000)) # Expected: 15

    # Test case 2
    print(nb_year(1500000, 2.5, 10000, 2000000)) # Expected: 10

    # Test case 3
    print(nb_year(1000, 2, 50, 1200)) # Expected: 3
    
    # Test case 4: Target population is less than or equal to initial population
    print(nb_year(1200, 2, 50, 1000)) # Expected: 0

    # Test case 5: Zero percent growth
    print(nb_year(1000, 0, 100, 2000)) # Expected: 10