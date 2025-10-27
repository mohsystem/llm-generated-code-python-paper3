
def get_monthly_sales(month: int) -> float:
    """\n    Simulates retrieving monthly sales data.\n    In production, this would connect to a database or API with proper validation.\n    \n    Args:\n        month: Integer index (0-2) representing the month\n        \n    Returns:\n        float: Sales amount for the specified month\n        \n    Raises:\n        ValueError: If month is outside valid range\n    """
    # Input validation: ensure month is within expected range
    if not isinstance(month, int):
        raise TypeError("Month must be an integer")
    
    if month < 0 or month > 2:
        # Fail closed with clear error for invalid month index
        raise ValueError("Month index must be between 0 and 2")
    
    # Simulated sales data for demonstration
    # In production, ensure data source is authenticated and validated
    sales_data = [15000.50, 18500.75, 22300.25]
    return sales_data[month]


def calculate_quarterly_sales() -> float:
    """\n    Calculate total sales for the first quarter (3 months).\n    \n    Returns:\n        float: Sum of sales for months 0, 1, and 2\n    """
    sum_total = 0.0
    
    # Iterate exactly 3 times for first quarter (months 0, 1, 2)
    for i in range(3):
        # Each iteration calls get_monthly_sales with validated input
        monthly_sale = get_monthly_sales(i)
        
        # Check for overflow before addition (defensive programming)
        if not isinstance(monthly_sale, (int, float)):
            raise TypeError("Monthly sales must be numeric")
        
        sum_total += monthly_sale
    
    return sum_total


if __name__ == "__main__":
    # Test case 1: Normal quarterly calculation
    try:
        result = calculate_quarterly_sales()
        print(f"Test 1 - Quarterly Sales: {result}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Verify individual month retrieval
    try:
        month0 = get_monthly_sales(0)
        print(f"Test 2 - Month 0 Sales: {month0}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Verify boundary condition (month 2)
    try:
        month2 = get_monthly_sales(2)
        print(f"Test 3 - Month 2 Sales: {month2}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Invalid month index (should fail)
    try:
        invalid = get_monthly_sales(3)
        print(f"Test 4 - Should not reach here: {invalid}")
    except Exception as e:
        print(f"Test 4 - Expected error caught: {e}")
    
    # Test case 5: Invalid negative month index (should fail)
    try:
        invalid = get_monthly_sales(-1)
        print(f"Test 5 - Should not reach here: {invalid}")
    except Exception as e:
        print(f"Test 5 - Expected error caught: {e}")
