
import random

def get_monthly_sales():
    return random.randint(0, 100000)

def calculate_quarterly_sales():
    monthly_sales = []
    
    # Get monthly sales for all 12 months
    for i in range(12):
        monthly_sales.append(get_monthly_sales())
    
    # Calculate quarterly sales
    q1 = monthly_sales[0] + monthly_sales[1] + monthly_sales[2]
    q2 = monthly_sales[3] + monthly_sales[4] + monthly_sales[5]
    q3 = monthly_sales[6] + monthly_sales[7] + monthly_sales[8]
    q4 = monthly_sales[9] + monthly_sales[10] + monthly_sales[11]
    
    # Print results
    print(f"Quarter 1 Sales: ${q1}")
    print(f"Quarter 2 Sales: ${q2}")
    print(f"Quarter 3 Sales: ${q3}")
    print(f"Quarter 4 Sales: ${q4}")
    print(f"Total Annual Sales: ${q1 + q2 + q3 + q4}")
    print()

if __name__ == "__main__":
    print("Test Case 1:")
    calculate_quarterly_sales()
    
    print("Test Case 2:")
    calculate_quarterly_sales()
    
    print("Test Case 3:")
    calculate_quarterly_sales()
    
    print("Test Case 4:")
    calculate_quarterly_sales()
    
    print("Test Case 5:")
    calculate_quarterly_sales()
