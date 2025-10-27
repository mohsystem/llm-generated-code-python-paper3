def get_monthly_sales(sales_data, month_index):
    """
    Simulates fetching monthly sales data for a given month index.
    As a security measure, it checks if the month_index is within the valid bounds of the list.
    Args:
        sales_data: A list containing sales data.
        month_index: The index of the month (0-based).
    Returns:
        The sales figure for the given month, or 0.0 if the index is invalid.
    """
    if 0 <= month_index < len(sales_data):
        return sales_data[month_index]
    else:
        # Handle invalid index to prevent crashes and return a safe value.
        return 0.0

def calculate_first_quarter_sales(yearly_sales):
    """
    Calculates the total sales for the first quarter (first 3 months)
    by iterating and summing up the sales for each month.
    Args:
        yearly_sales: A list containing at least 3 months of sales data.
    Returns:
        The total sum of sales for the first quarter.
    """
    # Python's numbers handle arbitrary size, so overflow is not an issue.
    total_sum = 0.0
    
    # The for loop iterates 3 times (for i = 0, 1, and 2) for the first quarter.
    for i in range(3):
        # On each iteration, the loop calls get_monthly_sales with the current value of i.
        # The return value is added to total_sum.
        total_sum += get_monthly_sales(yearly_sales, i)
        
    # After the loop, total_sum contains the total sales for the first quarter.
    return total_sum

def main():
    """ Main function to run test cases. """
    # --- 5 Test Cases ---

    # Test Case 1: Standard sales data
    sales1 = [10000.50, 15000.75, 12500.00, 18000.25]
    print(f"Test Case 1 - Expected: 37501.25, Actual: {calculate_first_quarter_sales(sales1)}")

    # Test Case 2: Sales data with a zero-sale month
    sales2 = [22000.00, 0.00, 25000.50, 21000.00]
    print(f"Test Case 2 - Expected: 47000.50, Actual: {calculate_first_quarter_sales(sales2)}")

    # Test Case 3: All sales figures are identical
    sales3 = [5000.00, 5000.00, 5000.00, 5000.00]
    print(f"Test Case 3 - Expected: 15000.00, Actual: {calculate_first_quarter_sales(sales3)}")

    # Test Case 4: Larger sales figures
    sales4 = [1234567.89, 9876543.21, 5555555.55, 9012345.67]
    print(f"Test Case 4 - Expected: 16666666.65, Actual: {calculate_first_quarter_sales(sales4)}")
    
    # Test Case 5: Input list with exactly 3 elements
    sales5 = [100.00, 200.00, 300.00]
    print(f"Test Case 5 - Expected: 600.00, Actual: {calculate_first_quarter_sales(sales5)}")

if __name__ == "__main__":
    main()