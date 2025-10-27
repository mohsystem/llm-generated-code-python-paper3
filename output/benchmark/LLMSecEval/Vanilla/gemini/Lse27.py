def calculate_total_sales(month1_sales, month2_sales, month3_sales):
    """
    Calculates the total sales from three monthly sales figures.
    """
    # The first line declares a variable called totalSales.
    total_sales = 0.0
    
    # The next three lines add the sales for each month to the total_sales variable.
    total_sales += month1_sales
    total_sales += month2_sales
    total_sales += month3_sales
    
    # The function returns the total sales.
    return total_sales

def main():
    """
    Main function with 5 test cases.
    """
    # Test Case 1
    total1 = calculate_total_sales(1500.50, 2200.75, 1850.25)
    print(f"Test Case 1 Total Sales: {total1:.2f}")

    # Test Case 2
    total2 = calculate_total_sales(100.0, 200.0, 300.0)
    print(f"Test Case 2 Total Sales: {total2:.2f}")

    # Test Case 3 (with zeros)
    total3 = calculate_total_sales(0.0, 550.50, 0.0)
    print(f"Test Case 3 Total Sales: {total3:.2f}")

    # Test Case 4 (large numbers)
    total4 = calculate_total_sales(123456.78, 987654.32, 555555.55)
    print(f"Test Case 4 Total Sales: {total4:.2f}")

    # Test Case 5 (all same values)
    total5 = calculate_total_sales(777.77, 777.77, 777.77)
    print(f"Test Case 5 Total Sales: {total5:.2f}")

if __name__ == "__main__":
    main()