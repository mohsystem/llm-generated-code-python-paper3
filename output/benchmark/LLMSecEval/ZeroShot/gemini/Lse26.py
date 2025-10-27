import sys

def get_monthly_sales(month_index, sales_data):
    """
    Retrieves the sales for a specific month from a data source.
    Secure: Performs type and bounds checking to prevent errors.

    Args:
        month_index (int): The index of the month (0-2).
        sales_data (list): A list containing monthly sales data.

    Returns:
        int or float: The sales for the given month, or 0 if the index is invalid.
    """
    if not isinstance(sales_data, list) or not 0 <= month_index < len(sales_data):
        # Handle invalid input gracefully.
        return 0
    return sales_data[month_index]

def calculate_first_quarter_sales(first_quarter_sales_data):
    """
    Calculates the total sales for the first quarter (first 3 months).
    The for loop iterates 3 times. On each iteration, it calls get_monthly_sales
    with the current loop index i. The return value is added to a running sum.

    Args:
        first_quarter_sales_data (list): A list with at least 3 elements
                                         representing sales for Jan, Feb, Mar.
    Returns:
        int or float: The sum of the first three months' sales.
    """
    # Python integers handle arbitrary size, naturally preventing overflow.
    total_sum = 0
    
    # The loop iterates 3 times for the first quarter (months 0, 1, 2).
    for i in range(3):
        # On each iteration, get the sales for the month and add to the sum.
        total_sum += get_monthly_sales(i, first_quarter_sales_data)
        
    return total_sum

def main():
    """ Main function with 5 test cases. """
    # 5 test cases to validate the functionality.
    test_cases = [
        [10000, 12000, 15000],          # Standard case
        [0, 0, 0],                      # All zero sales
        [sys.maxsize, 10, 20],          # Large value test
        [1500, 2500, 500],              # Small values
        [-100, 500, -200]               # Edge case with negative values (e.g., returns)
    ]

    print("Running 5 Python test cases...")
    for i, current_case in enumerate(test_cases):
        total_sales = calculate_first_quarter_sales(current_case)
        print(f"Test Case {i + 1}: {current_case} -> Total Sales: {total_sales}")

if __name__ == "__main__":
    main()