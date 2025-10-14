import math

def calculate_years(principal: float, interest: float, tax: float, desired: float) -> int:
    if any(math.isnan(x) or math.isinf(x) for x in (principal, interest, tax, desired)):
        return -1
    if desired <= principal:
        return 0
    net_rate = interest * (1.0 - tax)
    if net_rate <= 0.0:
        return -1

    years = 0
    MAX_YEARS = 10_000_000
    p = principal
    while p < desired:
        interest_earned = p * interest
        after_tax_interest = interest_earned * (1.0 - tax)
        p += after_tax_interest
        years += 1
        if years > MAX_YEARS or math.isnan(p) or math.isinf(p):
            return -1
    return years

if __name__ == "__main__":
    tests = [
        (1000.0, 0.05, 0.18, 1100.0),
        (1000.0, 0.05, 0.18, 1000.0),
        (1000.0, 0.0,  0.18, 1100.0),
        (1200.0, 0.0175, 0.05, 1300.0),
        (1500.0, 0.07, 0.6, 2000.0),
    ]
    for idx, args in enumerate(tests, 1):
        print(f"Test {idx}: years = {calculate_years(*args)}")