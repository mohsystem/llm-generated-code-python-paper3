
import secrets

MAX_SALES = 100000

def get_monthly_sales():
    return secrets.randbelow(MAX_SALES + 1)

def calculate_quarterly_sales():
    q1 = sum(get_monthly_sales() for _ in range(3))
    q2 = sum(get_monthly_sales() for _ in range(3))
    q3 = sum(get_monthly_sales() for _ in range(3))
    q4 = sum(get_monthly_sales() for _ in range(3))
    
    print("Quarterly Sales Report:")
    print(f"Q1 Sales: ${q1}")
    print(f"Q2 Sales: ${q2}")
    print(f"Q3 Sales: ${q3}")
    print(f"Q4 Sales: ${q4}")
    print(f"Total Annual Sales: ${q1 + q2 + q3 + q4}")
    print()

if __name__ == "__main__":
    print("Running 5 test cases:\\n")
    for i in range(1, 6):
        print(f"Test Case {i}:")
        calculate_quarterly_sales()
