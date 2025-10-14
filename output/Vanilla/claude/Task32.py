
def calculate_years(principal, interest, tax, desired):
    if principal >= desired:
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
    # Test case 1: Example from problem
    print(f"Test 1: {calculate_years(1000.00, 0.05, 0.18, 1100.00)} (Expected: 3)")
    
    # Test case 2: Principal equals desired
    print(f"Test 2: {calculate_years(1000.00, 0.05, 0.18, 1000.00)} (Expected: 0)")
    
    # Test case 3: Small growth needed
    print(f"Test 3: {calculate_years(1000.00, 0.10, 0.10, 1050.00)} (Expected: 1)")
    
    # Test case 4: Large growth needed
    print(f"Test 4: {calculate_years(1000.00, 0.01, 0.18, 1200.00)} (Expected: 25)")
    
    # Test case 5: High interest, low tax
    print(f"Test 5: {calculate_years(1000.00, 0.20, 0.10, 2000.00)} (Expected: 4)")
