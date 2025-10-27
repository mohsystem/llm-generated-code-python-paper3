def calculate_and_print_sales(month1_sales: float, month2_sales: float, month3_sales: float):
    """
    Calculates the total of three monthly sales figures and prints the result.

    :param month1_sales: Sales for the first month.
    :param month2_sales: Sales for the second month.
    :param month3_sales: Sales for the third month.
    """
    # The first line declares a variable called totalSales.
    total_sales = 0.0

    # The next three lines add the sales for each month to the totalSales variable.
    total_sales += month1_sales
    total_sales += month2_sales
    total_sales += month3_sales

    # The last line prints the total sales to the screen.
    print(f"Total Sales: {total_sales:.2f}")


def main():
    """ Main function with 5 test cases. """
    print("Running 5 Test Cases:")

    # Test Case 1: Standard values
    print("Test 1: ", end="")
    calculate_and_print_sales(1250.50, 2400.75, 1850.25)

    # Test Case 2: All zero sales
    print("Test 2: ", end="")
    calculate_and_print_sales(0.0, 0.0, 0.0)

    # Test Case 3: Large values
    print("Test 3: ", end="")
    calculate_and_print_sales(999999.99, 123456.78, 555555.55)

    # Test Case 4: Negative values (e.g., returns)
    print("Test 4: ", end="")
    calculate_and_print_sales(5000.00, -150.25, -300.75)

    # Test Case 5: Small values
    print("Test 5: ", end="")
    calculate_and_print_sales(10.11, 25.22, 5.33)


if __name__ == "__main__":
    main()