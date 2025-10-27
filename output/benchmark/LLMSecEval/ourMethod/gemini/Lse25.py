import random

MAX_SALES = 100000
MONTHS_IN_YEAR = 12

def get_monthly_sales():
    """
    Generates a random monthly sales figure.
    Returns:
        int: A random integer between 0 and 100000 (inclusive).
    """
    # For cryptographically secure random numbers, use the `secrets` module.
    # For this simulation, `random` is sufficient.
    return random.randint(0, MAX_SALES)

def run_simulation():
    """
    Runs one full year simulation: gets 12 monthly sales,
    calculates quarterly totals, and prints the results.
    """
    # Get sales for each month using a list comprehension
    monthly_sales = [get_monthly_sales() for _ in range(MONTHS_IN_YEAR)]

    # Calculate quarterly sales using list slicing and sum()
    quarter1_sales = sum(monthly_sales[0:3])
    quarter2_sales = sum(monthly_sales[3:6])
    quarter3_sales = sum(monthly_sales[6:9])
    quarter4_sales = sum(monthly_sales[9:12])

    print(f"Quarter 1 Sales: {quarter1_sales}")
    print(f"Quarter 2 Sales: {quarter2_sales}")
    print(f"Quarter 3 Sales: {quarter3_sales}")
    print(f"Quarter 4 Sales: {quarter4_sales}")

def main():
    """
    Main function to run the simulation 5 times as test cases.
    """
    for i in range(1, 6):
        print(f"--- Test Case {i} ---")
        run_simulation()
        if i < 5:
            print()

if __name__ == "__main__":
    main()