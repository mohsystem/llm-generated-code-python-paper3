import typing

def get_monthly_sales(month: int, monthly_sales_data: typing.List[float]) -> float:
    """
    Simulates fetching monthly sales data.

    Args:
        month: The month index (0 for January, 1 for February, etc.).
        monthly_sales_data: A list containing sales data for each month.

    Returns:
        The sales for the given month. Returns 0.0 if the month is out of bounds.
    """
    # Input validation
    if isinstance(monthly_sales_data, list) and 0 <= month < len(monthly_sales_data):
        return monthly_sales_data[month]
    return 0.0 # Fail safe

def calculate_first_quarter_sales(sales_data: typing.List[float]) -> float:
    """
    Calculates the total sales for the first quarter (first 3 months).

    Args:
        sales_data: A list containing at least 3 months of sales data.

    Returns:
        The total sales for the first quarter.
    """
    # Input validation
    if not isinstance(sales_data, list) or len(sales_data) < 3:
        return 0.0

    total_sum = 0.0
    # The for loop iterates 3 times for the first quarter (months 0, 1, 2).
    for i in range(3):
        # On each iteration, the loop calls get_monthly_sales with the current value of i.
        # The return value is added to total_sum.
        total_sum += get_monthly_sales(i, sales_data)
    
    # After the loop, total_sum contains the total sales for the first quarter.
    return total_sum

def main():
    """Main function with 5 test cases."""
    print("--- 5 Test Cases ---")

    # Test Case 1: Standard sales data
    sales1 = [1500.50, 2200.00, 1850.75, 3000.00]
    print(f"Test Case 1 Total: {calculate_first_quarter_sales(sales1):.2f}") # Expected: 5551.25

    # Test Case 2: Sales data with zeros
    sales2 = [1000.00, 0.00, 500.00]
    print(f"Test Case 2 Total: {calculate_first_quarter_sales(sales2):.2f}") # Expected: 1500.00

    # Test Case 3: High value sales data
    sales3 = [100000.00, 150000.50, 125000.25, 90000.00]
    print(f"Test Case 3 Total: {calculate_first_quarter_sales(sales3):.2f}") # Expected: 375000.75

    # Test Case 4: Insufficient data (less than 3 months)
    sales4 = [500.00, 600.00]
    print(f"Test Case 4 Total: {calculate_first_quarter_sales(sales4):.2f}") # Expected: 0.00

    # Test Case 5: Invalid data type (not a list)
    sales5 = None
    print(f"Test Case 5 Total: {calculate_first_quarter_sales(sales5):.2f}") # Expected: 0.00

if __name__ == "__main__":
    main()