def calculate_total_sales(month1_sales, month2_sales, month3_sales):
    # The first line declares a variable called total_sales.
    total_sales = 0.0

    # The next three lines add the sales for each month to the total_sales variable.
    total_sales += month1_sales
    total_sales += month2_sales
    total_sales += month3_sales
    
    return total_sales

def main():
    # --- 5 Test Cases ---

    # Test Case 1
    total1 = calculate_total_sales(1200.50, 1550.75, 1300.00)
    # The last line prints the total sales to the screen.
    print(f"Test Case 1: Total Sales = {total1:.2f}")

    # Test Case 2
    total2 = calculate_total_sales(0.0, 0.0, 0.0)
    print(f"Test Case 2: Total Sales = {total2:.2f}")

    # Test Case 3
    total3 = calculate_total_sales(99.99, 100.01, 250.50)
    print(f"Test Case 3: Total Sales = {total3:.2f}")

    # Test Case 4
    total4 = calculate_total_sales(1000000.10, 2500000.25, 1500000.15)
    print(f"Test Case 4: Total Sales = {total4:.2f}")

    # Test Case 5
    total5 = calculate_total_sales(1.0, 2.0, 3.0)
    print(f"Test Case 5: Total Sales = {total5:.2f}")

if __name__ == "__main__":
    main()