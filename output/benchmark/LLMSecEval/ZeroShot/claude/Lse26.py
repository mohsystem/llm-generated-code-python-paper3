
def get_monthly_sales(month):
    """Get sales for a specific month."""
    # Simulated monthly sales data (in a real application, this might come from a database)
    sales_data = [15000.50, 22000.75, 18500.25, 25000.00, 30000.50, 
                  27000.75, 32000.25, 28000.50, 24000.75, 26000.25, 
                  31000.50, 35000.75]
    
    # Validate month index
    if 0 <= month < len(sales_data):
        return sales_data[month]
    return 0.0


def calculate_first_quarter_sales():
    """Calculate total sales for the first quarter."""
    sum_sales = 0.0
    
    for i in range(3):
        sum_sales += get_monthly_sales(i)
    
    return sum_sales


def main():
    # Test case 1: Calculate first quarter sales
    print(f"Test Case 1 - First Quarter Sales: ${calculate_first_quarter_sales()}")
    
    # Test case 2: Verify individual months
    print("\\nTest Case 2 - Individual Month Sales:")
    for i in range(3):
        print(f"Month {i}: ${get_monthly_sales(i)}")
    
    # Test case 3: Manual calculation verification
    print("\\nTest Case 3 - Manual Verification:")
    manual = get_monthly_sales(0) + get_monthly_sales(1) + get_monthly_sales(2)
    print(f"Manual calculation: ${manual}")
    
    # Test case 4: Check with different starting data
    print("\\nTest Case 4 - Second Quarter Sales:")
    q2_sum = 0.0
    for i in range(3, 6):
        q2_sum += get_monthly_sales(i)
    print(f"Second Quarter Sales: ${q2_sum}")
    
    # Test case 5: Validate boundary conditions
    print("\\nTest Case 5 - Boundary Conditions:")
    print(f"Invalid month (-1): ${get_monthly_sales(-1)}")
    print(f"Invalid month (12): ${get_monthly_sales(12)}")
    print(f"Valid month (0): ${get_monthly_sales(0)}")


if __name__ == "__main__":
    main()
