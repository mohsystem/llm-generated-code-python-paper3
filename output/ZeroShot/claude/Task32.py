
def calculate_years(principal, interest, tax, desired):
    if desired <= principal:
        return 0
    
    years = 0
    current_amount = principal
    
    while current_amount < desired:
        year_interest = current_amount * interest
        tax_amount = year_interest * tax
        net_interest = year_interest - tax_amount
        current_amount += net_interest
        years += 1
    
    return years


if __name__ == "__main__":
    # Test case 1: Example from prompt
    print("Test 1:", calculate_years(1000, 0.05, 0.18, 1100))
    
    # Test case 2: Desired equals principal
    print("Test 2:", calculate_years(1000, 0.05, 0.18, 1000))
    
    # Test case 3: Higher interest rate
    print("Test 3:", calculate_years(1000, 0.10, 0.18, 1200))
    
    # Test case 4: Lower tax rate
    print("Test 4:", calculate_years(1500, 0.06, 0.10, 2000))
    
    # Test case 5: Large desired amount
    print("Test 5:", calculate_years(5000, 0.07, 0.15, 10000))
