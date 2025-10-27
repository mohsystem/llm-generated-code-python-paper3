
def get_monthly_sales(month):
    # Simulated monthly sales data
    sales = [15000.50, 22000.75, 18500.25, 20000.00, 25000.50, 
             19000.75, 21000.25, 23000.00, 17000.50, 24000.75, 
             26000.25, 28000.00]
    if 0 <= month < len(sales):
        return sales[month]
    return 0.0

def calculate_first_quarter_sales():
    sum_sales = 0.0
    for i in range(3):
        sum_sales += get_monthly_sales(i)
    return sum_sales

if __name__ == "__main__":
    # Test case 1: Calculate first quarter sales
    print(f"Test Case 1 - First Quarter Sales: ${calculate_first_quarter_sales()}")
    
    # Test case 2: Get individual monthly sales
    print(f"Test Case 2 - Month 0 Sales: ${get_monthly_sales(0)}")
    
    # Test case 3: Get individual monthly sales
    print(f"Test Case 3 - Month 1 Sales: ${get_monthly_sales(1)}")
    
    # Test case 4: Get individual monthly sales
    print(f"Test Case 4 - Month 2 Sales: ${get_monthly_sales(2)}")
    
    # Test case 5: Verify sum calculation
    manual_sum = get_monthly_sales(0) + get_monthly_sales(1) + get_monthly_sales(2)
    print(f"Test Case 5 - Manual Sum Verification: ${manual_sum}")
