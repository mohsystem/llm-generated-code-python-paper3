from typing import Union
import math

def years_to_target(principal: float, interest_rate: float, tax_rate: float, desired: float) -> int:
    """
    Computes the number of years needed to reach desired amount with yearly interest and tax on interest.
    Returns -1 for invalid inputs or if the target cannot be reached (e.g., non-positive growth when D > P).
    """
    # Validate inputs
    for v in (principal, interest_rate, tax_rate, desired):
        if not isinstance(v, (int, float)) or not math.isfinite(v):
            return -1
    if principal < 0.0 or desired < 0.0 or interest_rate < 0.0 or tax_rate < 0.0 or tax_rate > 1.0:
        return -1
    if desired <= principal:
        return 0

    effective_rate = interest_rate * (1.0 - tax_rate)
    if effective_rate <= 0.0:
        return -1  # Cannot reach higher desired amount without positive growth

    years = 0
    amount = float(principal)
    while amount < desired:
        interest = amount * interest_rate
        net_gain = interest * (1.0 - tax_rate)
        amount += net_gain
        years += 1
        if not math.isfinite(amount):
            return -1
    return years

def _run_test(p: float, i: float, t: float, d: float) -> None:
    y = years_to_target(p, i, t, d)
    print(f"P={p:.2f} I={i:.4f} T={t:.4f} D={d:.2f} => Years={y}")

if __name__ == "__main__":
    # 5 test cases
    _run_test(1000.00, 0.05, 0.18, 1100.00)  # Expected 3
    _run_test(5000.00, 0.05, 0.20, 5000.00)  # Expected 0
    _run_test(1000.00, 0.05, 1.20, 1100.00)  # Invalid tax, Expected -1
    _run_test(1000.00, 0.00, 0.18, 1001.00)  # Zero growth, Expected -1
    _run_test(1500.00, 0.07, 0.25, 2000.00)  # Expected 6