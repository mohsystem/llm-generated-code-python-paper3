def calculate_years(p, i, t, d):
    """
    Calculates the number of years to reach a desired sum with yearly interest and tax.

    :param p: The initial principal amount.
    :param i: The yearly interest rate (e.g., 0.05 for 5%).
    :param t: The tax rate on the interest earned (e.g., 0.18 for 18%).
    :param d: The desired final sum.
    :return: The number of years required.
    """
    if p >= d:
        return 0
    
    years = 0
    current_principal = p
    
    while current_principal < d:
        interest_earned = current_principal * i
        tax_on_interest = interest_earned * t
        current_principal += (interest_earned - tax_on_interest)
        years += 1
        
    return years

if __name__ == '__main__':
    # Test Case 1: Example from description
    print(f"Test Case 1: {calculate_years(1000.00, 0.05, 0.18, 1100.00)}") # Expected: 3

    # Test Case 2: Principal already meets or exceeds desired amount
    print(f"Test Case 2: {calculate_years(1000.00, 0.05, 0.18, 1000.00)}") # Expected: 0

    # Test Case 3: No tax
    print(f"Test Case 3: {calculate_years(1000.00, 0.05, 0.0, 1100.00)}")  # Expected: 2

    # Test Case 4: Higher desired amount
    print(f"Test Case 4: {calculate_years(1200.00, 0.05, 0.10, 2000.00)}") # Expected: 12

    # Test Case 5: Higher tax rate
    print(f"Test Case 5: {calculate_years(1000.00, 0.05, 0.50, 1100.00)}") # Expected: 4