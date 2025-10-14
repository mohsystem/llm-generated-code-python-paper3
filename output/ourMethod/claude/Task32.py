
from typing import Union
import math

def calculate_years(principal: float, interest_rate: float, tax_rate: float, desired: float) -> int:
    # Input validation
    if not all(isinstance(x, (int, float)) for x in [principal, interest_rate, tax_rate, desired]):
        raise TypeError("All parameters must be numeric")
    
    if principal < 0 or interest_rate < 0 or tax_rate < 0 or desired < 0:
        raise ValueError("All parameters must be non-negative")
    
    if interest_rate > 1 or tax_rate > 1:
        raise ValueError("Interest and tax rates must be between 0 and 1")
    
    if any(math.isnan(x) for x in [principal, interest_rate, tax_rate, desired]):
        raise ValueError("Parameters cannot be NaN")
    
    if any(math.isinf(x) for x in [principal, interest_rate, tax_rate, desired]):
        raise ValueError("Parameters cannot be infinite")
    
    # If desired is less than or equal to principal, return 0
    if desired <= principal:
        return 0
    
    # Calculate years needed
    years = 0
    current_amount = principal
    MAX_YEARS = 100000
    
    while current_amount < desired and years < MAX_YEARS:
        interest = current_amount * interest_rate
        tax_on_interest = interest * tax_rate
        net_interest = interest - tax_on_interest
        current_amount += net_interest
        years += 1
    
    if years >= MAX_YEARS:
        raise ArithmeticError("Maximum iteration limit reached")
    
    return years

def main():
    test_cases = [
        (1000.0, 0.05, 0.18, 1100.0, 3),
        (1000.0, 0.01, 0.18, 1000.0, 0),
        (1000.0, 0.05, 0.18, 1000.0, 0),
        (5000.0, 0.02, 0.18, 5100.0, 2),
        (100.0, 0.10, 0.25, 200.0, 10)
    ]
    
    for i, (principal, interest_rate, tax_rate, desired, expected) in enumerate(test_cases, 1):
        try:
            result = calculate_years(principal, interest_rate, tax_rate, desired)
            status = "PASS" if result == expected else "FAIL"
            print(f"Test {i}: Expected {expected}, Got {result} - {status}")
        except Exception as e:
            print(f"Test {i}: Exception - {str(e)}")

if __name__ == "__main__":
    main()
