from math import floor, isfinite

def nb_year(p0: int, percent: float, aug: int, p: int) -> int:
    # Validate inputs
    if not isinstance(p0, int) or not isinstance(p, int) or not isinstance(aug, int):
        return -1
    if not isinstance(percent, (int, float)):
        return -1
    if p0 <= 0 or p <= 0 or percent < 0.0 or not isfinite(percent):
        return -1

    if p0 >= p:
        return 0
    if percent == 0.0 and aug <= 0:
        return -1

    current = p0
    years = 0
    MAX_YEARS = 10_000_000

    while current < p:
        if years >= MAX_YEARS:
            return -1
        growth = int(current * (percent / 100.0))  # floors for non-negative percent
        next_val = current + growth + aug
        if next_val < 0:
            next_val = 0
        if next_val == current:
            return -1  # Stuck, cannot progress further
        current = next_val
        years += 1

    return years

if __name__ == "__main__":
    # 5 test cases
    print(nb_year(1000, 2.0, 50, 1200))           # Expected 3
    print(nb_year(1500, 5.0, 100, 5000))          # Expected 15
    print(nb_year(1500000, 2.5, 10000, 2000000))  # Expected 10
    print(nb_year(1000, 0.0, 0, 1000))            # Expected 0
    print(nb_year(1000, 0.0, -1, 1200))           # Expected -1 (unreachable)