
import random

def get_monthly_sales():
    return random.randint(0, 100000)

def calculate_quarterly_sales():
    q1_sales = 0
    q2_sales = 0
    q3_sales = 0
    q4_sales = 0
    
    # Quarter 1 (Jan, Feb, Mar)
    for i in range(3):
        q1_sales += get_monthly_sales()
    
    # Quarter 2 (Apr, May, Jun)
    for i in range(3):
        q2_sales += get_monthly_sales()
    
    # Quarter 3 (Jul, Aug, Sep)
    for i in range(3):
        q3_sales += get_monthly_sales()
    
    # Quarter 4 (Oct, Nov, Dec)
    for i in range(3):
        q4_sales += get_monthly_sales()
    
    print(f"Quarter 1 Sales: ${q1_sales}")
    print(f"Quarter 2 Sales: ${q2_sales}")
    print(f"Quarter 3 Sales: ${q3_sales}")
    print(f"Quarter 4 Sales: ${q4_sales}")
    print(f"Total Annual Sales: ${q1_sales + q2_sales + q3_sales + q4_sales}")

if __name__ == "__main__":
    # Test case 1
    print("Test Case 1:")
    calculate_quarterly_sales()
    
    # Test case 2
    print("\\nTest Case 2:")
    calculate_quarterly_sales()
    
    # Test case 3
    print("\\nTest Case 3:")
    calculate_quarterly_sales()
    
    # Test case 4
    print("\\nTest Case 4:")
    calculate_quarterly_sales()
    
    # Test case 5
    print("\\nTest Case 5:")
    calculate_quarterly_sales()
