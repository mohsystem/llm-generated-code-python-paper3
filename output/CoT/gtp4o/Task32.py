# Chain-of-Through process:
# 1) Problem understanding:
#    - Determine years for P to reach D with yearly interest I and tax T on interest.
# 2) Security requirements:
#    - Validate inputs; avoid infinite loops when no growth.
# 3) Secure coding generation:
#    - Defensive checks and clear loop logic.
# 4) Code review:
#    - Ensured finite checks, non-negative inputs, effective rate validation.
# 5) Secure code output:
#    - Return -1 for invalid/unreachable scenarios.

import math

def calculate_years(principal: float, interest: float, tax: float, desired: float) -> int:
    if not all(map(math.isfinite, [principal, interest, tax, desired])):
        return -1
    if principal < 0 or interest < 0 or tax < 0 or desired < 0:
        return -1
    if desired <= principal:
        return 0

    effective_rate = interest * (1.0 - tax)
    if effective_rate <= 0.0:
        return -1

    years = 0
    p = principal
    MAX_YEARS = 100_000_000
    while p < desired:
        interest_earned = p * interest
        p += interest_earned * (1.0 - tax)
        years += 1
        if years > MAX_YEARS:
            return -1
    return years

if __name__ == "__main__":
    print(calculate_years(1000.0, 0.05, 0.18, 1100.0))  # Expected: 3
    print(calculate_years(1000.0, 0.05, 0.18, 1000.0))  # Expected: 0
    print(calculate_years(1000.0, 0.00, 0.10, 1200.0))  # Expected: -1 (unreachable)
    print(calculate_years(1500.0, 0.07, 0.20, 2000.0))  # Expected: 6
    print(calculate_years(500.0, 0.05, 0.00, 525.0))    # Expected: 1