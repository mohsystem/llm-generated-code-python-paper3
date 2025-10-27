import random

def get_monthly_sales():
    """Returns a random number between 0 and 100000."""
    return random.randint(0, 100000)

def calculate_and_print_quarterly_sales():
    """
    Simulates a year of sales, calculates the total for each quarter,
    and prints the results.
    """
    quarter1_sales = 0
    quarter2_sales = 0
    quarter3_sales = 0
    quarter4_sales = 0

    # Loop through 12 months of the year
    for month in range(1, 13):
        monthly_sale = get_monthly_sales()
        if month <= 3:
            quarter1_sales += monthly_sale
        elif month <= 6:
            quarter2_sales += monthly_sale
        elif month <= 9:
            quarter3_sales += monthly_sale
        else:
            quarter4_sales += monthly_sale
            
    # Print the results for each quarter
    print(f"Quarter 1 Sales: {quarter1_sales}")
    print(f"Quarter 2 Sales: {quarter2_sales}")
    print(f"Quarter 3 Sales: {quarter3_sales}")
    print(f"Quarter 4 Sales: {quarter4_sales}")
    print("--------------------")

if __name__ == "__main__":
    # Run 5 test cases
    for i in range(5):
        print(f"Test Case {i + 1}")
        calculate_and_print_quarterly_sales()