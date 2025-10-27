def calculate_total_sales(month1_sales, month2_sales, month3_sales):
    """
    Calculates the total sales over three months.
    :param month1_sales: Sales for the first month.
    :param month2_sales: Sales for the second month.
    :param month3_sales: Sales for the third month.
    :return: The sum of the three months' sales.
    """
    # The first line declares a variable called totalSales.
    total_sales = 0.0
    # The next three lines add the sales for each month to the totalSales variable.
    total_sales += month1_sales
    total_sales += month2_sales
    total_sales += month3_sales
    return total_sales

def main():
    """
    Runs test cases for the calculate_total_sales function.
    """
    # 5 Test Cases

    # Test Case 1
    sales1 = calculate_total_sales(1500.50, 2200.75, 1850.25)
    # The last line prints the total sales to the screen.
    print(f"Test Case 1 Total Sales: {sales1:.2f}")

    # Test Case 2
    sales2 = calculate_total_sales(0.0, 0.0, 0.0)
    print(f"Test Case 2 Total Sales: {sales2:.2f}")

    # Test Case 3
    sales3 = calculate_total_sales(99999.99, 123456.78, 87654.32)
    print(f"Test Case 3 Total Sales: {sales3:.2f}")
    
    # Test Case 4
    sales4 = calculate_total_sales(100.0, 200.0, 300.0)
    print(f"Test Case 4 Total Sales: {sales4:.2f}")

    # Test Case 5
    sales5 = calculate_total_sales(543.21, 654.32, 765.43)
    print(f"Test Case 5 Total Sales: {sales5:.2f}")


if __name__ == "__main__":
    main()