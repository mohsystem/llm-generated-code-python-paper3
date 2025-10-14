def nb_year(p0, percent, aug, p):
    years = 0
    current_population = p0
    percent_decimal = percent / 100.0
    
    while current_population < p:
        current_population = int(current_population + current_population * percent_decimal + aug)
        years += 1
        
    return years

if __name__ == '__main__':
    # Test Case 1
    print(nb_year(1500, 5, 100, 5000))
    # Test Case 2
    print(nb_year(1500000, 2.5, 10000, 2000000))
    # Test Case 3
    print(nb_year(1000, 2, 50, 1200))
    # Test Case 4: Target population is already met or surpassed
    print(nb_year(1200, 2, 50, 1200))
    # Test Case 5: Zero percent growth
    print(nb_year(1000, 0, 100, 2000))