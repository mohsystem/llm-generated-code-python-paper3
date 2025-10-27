import secrets
from typing import Callable, List

def get_monthly_sales(randbelow_func: Callable[[int], int]) -> int:
    # Returns a random monthly sales figure between 0 and 100000 (inclusive)
    val = randbelow_func(100001)
    return int(val)

def compute_quarterly_sales(randbelow_func: Callable[[int], int]) -> List[int]:
    quarters = [0, 0, 0, 0]
    for month in range(12):
        sale = get_monthly_sales(randbelow_func)
        quarters[month // 3] += sale
    return quarters

def main() -> None:
    for t in range(1, 6):
        quarters = compute_quarterly_sales(secrets.randbelow)
        print("Test {} - Quarterly sales: Q1={}, Q2={}, Q3={}, Q4={}".format(
            t, quarters[0], quarters[1], quarters[2], quarters[3]
        ))

if __name__ == "__main__":
    main()