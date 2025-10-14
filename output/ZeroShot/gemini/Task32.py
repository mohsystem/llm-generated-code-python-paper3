def calculate_years(principal, interest, tax, desired):
    """
    Calculates the number of years to reach a desired sum.

    :param principal: The initial principal amount.
    :param interest: The annual interest rate (e.g., 0.05 for 5%).
    :param tax: The tax rate on interest earned (e.g., 0.18 for 18%).
    :param desired: The desired final sum.
    :return: The number of whole years required.
    """
    if principal >= desired:
        return 0

    years = 0
    current_principal = principal

    # Assuming interest is positive and tax is less than 1 to avoid infinite loops
    while current_principal < desired:
        interest_earned = current_principal * interest
        tax_paid = interest_earned * tax
        current_principal += (interest_earned - tax_paid)
        years += 1
    
    return years

if __name__ == "__main__":
    # Test Case 1: From description
    print(f"Test Case 1: {calculate_years(1000.00, 0.05, 0.18, 1100.00)}") # Expected: 3

    # Test Case 2: Desired amount is already met
    print(f"Test Case 2: {calculate_years(1000.00, 0.05, 0.18, 1000.00)}") # Expected: 0

    # Test Case 3: Larger growth needed
    print(f"Test Case 3: {calculate_years(100.00, 0.10, 0.20, 200.00)}") # Expected: 10

    # Test Case 4: No tax
    print(f"Test Case 4: {calculate_years(100.00, 0.10, 0.0, 150.00)}") # Expected: 5

    # Test Case 5: High tax
    print(f"Test Case 5: {calculate_years(1000.00, 0.08, 0.50, 1100.00)}") # Expected: 3