
def nb_year(p0, percent, aug, p):
    years = 0
    current_population = p0
    percent_decimal = percent / 100.0
    
    while current_population < p:
        current_population = int(current_population + current_population * percent_decimal + aug)
        years += 1
    
    return years

# Test cases
if __name__ == "__main__":
    print("Test 1:", nb_year(1000, 2, 50, 1200), "(Expected: 3)")
    print("Test 2:", nb_year(1500, 5, 100, 5000), "(Expected: 15)")
    print("Test 3:", nb_year(1500000, 2.5, 10000, 2000000), "(Expected: 10)")
    print("Test 4:", nb_year(1000, 2, 0, 1200), "(Expected: 10)")
    print("Test 5:", nb_year(1000, 0, 50, 1500), "(Expected: 10)")
