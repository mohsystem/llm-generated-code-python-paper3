
def calculate_total_sales(month1, month2, month3):
    total_sales = 0.0
    total_sales += month1
    total_sales += month2
    total_sales += month3
    return total_sales

def main():
    # Test case 1
    result1 = calculate_total_sales(1000.50, 2000.75, 1500.25)
    print(f"Test 1 - Total Sales: ${result1:.2f}")
    
    # Test case 2
    result2 = calculate_total_sales(5000.00, 3000.00, 4000.00)
    print(f"Test 2 - Total Sales: ${result2:.2f}")
    
    # Test case 3
    result3 = calculate_total_sales(750.30, 890.60, 1200.10)
    print(f"Test 3 - Total Sales: ${result3:.2f}")
    
    # Test case 4
    result4 = calculate_total_sales(0.00, 0.00, 0.00)
    print(f"Test 4 - Total Sales: ${result4:.2f}")
    
    # Test case 5
    result5 = calculate_total_sales(12345.67, 23456.78, 34567.89)
    print(f"Test 5 - Total Sales: ${result5:.2f}")

if __name__ == "__main__":
    main()
