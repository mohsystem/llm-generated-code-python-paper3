def get_monthly_sales(month, sales_data):
    """
    A mock function to get sales for a given month (0-indexed) from a data source.
    
    Args:
        month (int): The month index (0 for Jan, 1 for Feb, etc.).
        sales_data (list): A list containing monthly sales data.
    
    Returns:
        float: The sales amount for the given month.
    """
    if 0 <= month < len(sales_data):
        return sales_data[month]
    return 0.0

def calculate_first_quarter_sales(sales_data):
    """
    Calculates the total sales for the first quarter (first 3 months).
    
    Args:
        sales_data (list): A list containing at least 3 months of sales data.
    
    Returns:
        float: The total sales for the first quarter.
    """
    total_sum = 0.0
    # The for loop iterates 3 times starting at 0 and ending at 2.
    for i in range(3):
        # On each iteration the loop calls get_monthly_sales with the current value of i.
        monthly_sale = get_monthly_sales(i, sales_data)
        # The return value of get_monthly_sales is added to total_sum.
        total_sum += monthly_sale
    # After the loop; total_sum contains the total sales for the first quarter.
    return total_sum

def main():
    """Main function to run test cases."""
    print("--- Python: 5 Test Cases ---")
    
    # Test Case 1
    sales1 = [1000.50, 1200.75, 1100.25, 1300.00]
    total1 = calculate_first_quarter_sales(sales1)
    print(f"Test Case 1: First quarter sales: {total1:.2f}")

    # Test Case 2
    sales2 = [2500.00, 2600.00, 2700.00, 2800.00]
    total2 = calculate_first_quarter_sales(sales2)
    print(f"Test Case 2: First quarter sales: {total2:.2f}")

    # Test Case 3
    sales3 = [99.99, 100.01, 250.50, 300.00]
    total3 = calculate_first_quarter_sales(sales3)
    print(f"Test Case 3: First quarter sales: {total3:.2f}")

    # Test Case 4: All zero sales
    sales4 = [0.0, 0.0, 0.0, 100.0]
    total4 = calculate_first_quarter_sales(sales4)
    print(f"Test Case 4: First quarter sales: {total4:.2f}")

    # Test Case 5: Large numbers
    sales5 = [1500000.78, 2300000.45, 1950000.12, 2100000.00]
    total5 = calculate_first_quarter_sales(sales5)
    print(f"Test Case 5: First quarter sales: {total5:.2f}")

if __name__ == "__main__":
    main()