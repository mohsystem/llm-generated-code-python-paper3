def calculate_years(principal, interest, tax, desired):
    if principal >= desired:
        return 0
    years = 0
    p = principal
    while p < desired:
        p += p * interest * (1 - tax)
        years += 1
    return years

if __name__ == "__main__":
    print(calculate_years(1000.0, 0.05, 0.18, 1100.0))  # 3
    print(calculate_years(1000.0, 0.05, 0.18, 1000.0))  # 0
    print(calculate_years(1000.0, 0.05, 0.0, 1100.0))   # 2
    print(calculate_years(1000.0, 0.01625, 0.18, 1200.0))  # 14
    print(calculate_years(1500.0, 0.07, 0.60, 2000.0))  # 11