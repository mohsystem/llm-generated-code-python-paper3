
# Simulated monthly sales data
MONTHLY_SALES = [
    15000.0, 18000.0, 16500.0, 20000.0,
    17500.0, 19000.0, 21000.0, 18500.0,
    16000.0, 22000.0, 19500.0, 23000.0
]

def get_monthly_sales(month):
    """\n    Secure method to get monthly sales with input validation\n    """
    # Validate month index to prevent out-of-bounds access
    if not isinstance(month, int):
        raise TypeError("Month index must be an integer")
    
    if month < 0 or month >= len(MONTHLY_SALES):
        raise ValueError(f"Invalid month index: {month}")
    
    return MONTHLY_SALES[month]

def calculate_first_quarter_sales():
    """\n    Calculate first quarter sales by summing months 0-2\n    """
    sum_sales = 0.0
    
    # Iterate through first 3 months (index 0 to 2)
    for i in range(3):
        monthly_sale = get_monthly_sales(i)
        
        # Check for valid sales value
        if monthly_sale < 0:
            raise ValueError("Sales value cannot be negative")
        
        sum_sales += monthly_sale
    
    return sum_sales

if __name__ == "__main__":
    print("Test Case 1: First Quarter Sales")
    print(f"Total: ${calculate_first_quarter_sales()}")
    
    print("\\nTest Case 2: Individual Monthly Sales")
    for i in range(3):
        print(f"Month {i}: ${get_monthly_sales(i)}")
    
    print("\\nTest Case 3: Verify sum calculation")
    manual = get_monthly_sales(0) + get_monthly_sales(1) + get_monthly_sales(2)
    print(f"Manual calculation: ${manual}")
    
    print("\\nTest Case 4: Valid month access")
    print(f"Month 5 sales: ${get_monthly_sales(5)}")
    
    print("\\nTest Case 5: Error handling")
    try:
        get_monthly_sales(15)  # Invalid month
    except ValueError as e:
        print(f"Caught exception: {e}")
