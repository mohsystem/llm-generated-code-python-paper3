from typing import Union

def calculate_years(principal: Union[int, float], interest: float, tax: float, desired: Union[int, float]) -> int:
    """
    Calculates the number of years to reach a desired sum with compound interest and taxes.
    
    :param principal: The initial principal amount.
    :param interest: The annual interest rate (e.g., 0.05 for 5%).
    :param tax: The tax rate on the interest earned (e.g., 0.18 for 18%).
    :param desired: The desired final sum of money.
    :return: The number of years as a whole number.
    """
    if desired <= principal:
        return 0

    years = 0
    current_principal = float(principal)

    # The problem's constraints assume the principal will always grow towards the desired sum.
    while current_principal < desired:
        interest_earned = current_principal * interest
        tax_on_interest = interest_earned * tax
        current_principal += interest_earned - tax_on_interest
        years += 1

    return years

if __name__ == '__main__':
    # Test Case 1: Example from prompt
    print(f"Test Case 1 (P=1000, I=0.05, T=0.18, D=1100): {calculate_years(1000.0, 0.05, 0.18, 1100.0)}") # Expected: 3

    # Test Case 2: Desired sum is already met
    print(f"Test Case 2 (P=1000, I=0.05, T=0.18, D=1000): {calculate_years(1000.0, 0.05, 0.18, 1000.0)}") # Expected: 0

    # Test Case 3: Longer term investment
    print(f"Test Case 3 (P=100, I=0.02, T=0.1, D=120): {calculate_years(100.0, 0.02, 0.1, 120.0)}") # Expected: 11

    # Test Case 4: High interest, low tax
    print(f"Test Case 4 (P=5000, I=0.1, T=0.1, D=6000): {calculate_years(5000.0, 0.1, 0.1, 6000.0)}") # Expected: 3
    
    # Test Case 5: Just crossing the threshold
    print(f"Test Case 5 (P=2000, I=0.03, T=0.2, D=2100): {calculate_years(2000.0, 0.03, 0.2, 2100.0)}") # Expected: 3