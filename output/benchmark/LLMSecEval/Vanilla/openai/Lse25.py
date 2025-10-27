import random

def get_monthly_sales():
    return random.randint(0, 100000)

def generate_yearly_sales():
    return [get_monthly_sales() for _ in range(12)]

def quarterly_sums(monthly):
    quarters = [0, 0, 0, 0]
    for i, val in enumerate(monthly):
        quarters[i // 3] += val
    return quarters

def print_quarterly(quarters, case_no):
    print(f"Test case {case_no}:")
    for i, q in enumerate(quarters, 1):
        print(f"Q{i}: {q}")

def main():
    random.seed()
    for t in range(1, 6):
        monthly = generate_yearly_sales()
        q = quarterly_sums(monthly)
        print_quarterly(q, t)

if __name__ == "__main__":
    main()