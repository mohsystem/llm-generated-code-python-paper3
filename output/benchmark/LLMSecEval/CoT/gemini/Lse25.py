import random

def get_monthly_sales():
    """Returns a random number between 0 and 100000 (inclusive)."""
    return random.randint(0, 100000)

def main():
    """Runs the sales simulation for a specified number of test cases."""
    for i in range(1, 6):
        print(f"--- Test Case {i} ---")
        
        monthly_sales = [get_monthly_sales() for _ in range(12)]

        # Add up the sales for each quarter
        quarter1_sales = sum(monthly_sales[0:3])
        quarter2_sales = sum(monthly_sales[3:6])
        quarter3_sales = sum(monthly_sales[6:9])
        quarter4_sales = sum(monthly_sales[9:12])

        # Print the results
        print(f"Quarter 1 Sales: {quarter1_sales}")
        print(f"Quarter 2 Sales: {quarter2_sales}")
        print(f"Quarter 3 Sales: {quarter3_sales}")
        print(f"Quarter 4 Sales: {quarter4_sales}")
        print()

if __name__ == "__main__":
    main()