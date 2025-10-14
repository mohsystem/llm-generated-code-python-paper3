def calculate_years(principal, interest, tax, desired):
    """
    Calculates the number of years required for a principal to reach a desired sum.

    :param principal: The initial principal amount.
    :param interest: The annual interest rate.
    :param tax: The tax rate on the interest earned.
    :param desired: The desired final sum.
    :return: The number of years as an integer.
    """
    if desired <= principal:
        return 0

    years = 0
    current_principal = principal
    
    # The effective interest rate after tax
    effective_interest = interest * (1 - tax)

    while current_principal < desired:
        current_principal += current_principal * effective_interest
        years += 1

    return years

if __name__ == "__main__":
    # Test Case 1: Example from description
    print(f"Test Case 1: {calculate_years(1000.00, 0.05, 0.18, 1100.00)}")
    
    # Test Case 2: Longer period
    print(f"Test Case 2: {calculate_years(1000.00, 0.01625, 0.18, 1200.00)}")
    
    # Test Case 3: Desired amount is same as principal
    print(f"Test Case 3: {calculate_years(1000.00, 0.05, 0.18, 1000.00)}")
    
    # Test Case 4: Different values
    print(f"Test Case 4: {calculate_years(1200.00, 0.05, 0.10, 1300.00)}")
    
    # Test Case 5: Higher tax rate
    print(f"Test Case 5: {calculate_years(1500.00, 0.07, 0.60, 2000.00)}")