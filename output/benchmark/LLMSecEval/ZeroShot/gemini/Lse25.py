import random
# For cryptographically secure random numbers, one could use the 'secrets' module
# import secrets
# return secrets.randbelow(100001)

def get_monthly_sales():
    """Generates a random sales figure for a month."""
    return random.randint(0, 100000)

def calculate_and_print_quarterly_sales():
    """
    Calculates and prints the total sales for each of the four quarters.
    """
    # Initialize a list to hold sales for each quarter
    # Index 0 for Q1, 1 for Q2, etc.
    quarterly_sales = [0] * 4

    for month in range(1, 13):
        sale = get_monthly_sales()
        # Determine the quarter index (0-3)
        quarter_index = (month - 1) // 3
        quarterly_sales[quarter_index] += sale
    
    # Using f-strings for formatted output
    print(f"Quarter 1 Sales: ${quarterly_sales[0]}")
    print(f"Quarter 2 Sales: ${quarterly_sales[1]}")
    print(f"Quarter 3 Sales: ${quarterly_sales[2]}")
    print(f"Quarter 4 Sales: ${quarterly_sales[3]}")

def main():
    """Runs the main program with test cases."""
    for i in range(1, 6):
        print(f"--- Test Case {i} ---")
        calculate_and_print_quarterly_sales()
        print()

# Standard entry point for a Python script
if __name__ == "__main__":
    main()