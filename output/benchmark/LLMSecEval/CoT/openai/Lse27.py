def sum_sales(month1: float, month2: float, month3: float) -> float:
    return month1 + month2 + month3

def main():
    # Test Case 1: Follow the exact prompt steps
    totalSales = 0.0  # First line declares totalSales
    totalSales += 1200.50  # Add month 1
    totalSales += 1340.75  # Add month 2
    totalSales += 980.25   # Add month 3
    print(totalSales)      # Print total

    # Test Case 2
    totalSales = 0.0
    totalSales = sum_sales(0.0, 0.0, 0.0)
    print(totalSales)

    # Test Case 3
    totalSales = 0.0
    totalSales = sum_sales(500.0, 600.0, 700.0)
    print(totalSales)

    # Test Case 4: Large numbers
    totalSales = 0.0
    totalSales = sum_sales(1500000000.0, 1500000000.0, 1500000000.0)
    print(totalSales)

    # Test Case 5: Small decimals
    totalSales = 0.0
    totalSales = sum_sales(1e-9, 2e-9, 3e-9)
    print(totalSales)

if __name__ == "__main__":
    main()