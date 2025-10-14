
def calculate_years(principal, interest, tax, desired):
    # Input validation
    if principal <= 0 or desired <= 0 or interest < 0 or interest > 1 or tax < 0 or tax > 1:
        raise ValueError("Invalid input parameters")
    
    # Edge case: desired sum already reached
    if desired <= principal:
        return 0
    
    # Safety limit to prevent infinite loops
    MAX_YEARS = 1000
    years = 0
    current_principal = principal
    
    while current_principal < desired and years < MAX_YEARS:
        year_interest = current_principal * interest
        after_tax = year_interest * (1 - tax)
        current_principal += after_tax
        years += 1
    
    return years


if __name__ == "__main__":
    # Test case 1: Example from problem
    print(f"Test 1: {calculate_years(1000, 0.05, 0.18, 1100)} years (Expected: 3)")
    
    # Test case 2: Already at desired sum
    print(f"Test 2: {calculate_years(1000, 0.05, 0.18, 1000)} years (Expected: 0)")
    
    # Test case 3: Higher interest rate
    print(f"Test 3: {calculate_years(1000, 0.10, 0.18, 1200)} years (Expected: 3)")
    
    # Test case 4: Lower tax rate
    print(f"Test 4: {calculate_years(1000, 0.05, 0.10, 1100)} years (Expected: 2)")
    
    # Test case 5: Larger gap
    print(f"Test 5: {calculate_years(1000, 0.05, 0.18, 2000)} years (Expected: 17)")
