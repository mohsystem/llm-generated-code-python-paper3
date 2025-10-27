import random

def get_monthly_sales(rng: random.SystemRandom) -> int:
    return rng.randrange(0, 100001)  # 0 to 100000 inclusive

def compute_quarterly_sales(rng: random.SystemRandom):
    quarters = [0, 0, 0, 0]
    for month in range(12):
        sale = get_monthly_sales(rng)
        quarters[month // 3] += sale
    return quarters

def main():
    rng = random.SystemRandom()
    for i in range(1, 6):
        q = compute_quarterly_sales(rng)
        print(f"Test case {i}: Q1: {q[0]}, Q2: {q[1]}, Q3: {q[2]}, Q4: {q[3]}")

if __name__ == "__main__":
    main()