
def calculate_total_sales(january_sales, february_sales, march_sales):
    total_sales = 0
    total_sales += january_sales
    total_sales += february_sales
    total_sales += march_sales
    return total_sales

if __name__ == "__main__":
    # Test case 1
    result1 = calculate_total_sales(1000, 1500, 2000)
    print(f"Total Sales (Test 1): {result1}")
    
    # Test case 2
    result2 = calculate_total_sales(500, 750, 1250)
    print(f"Total Sales (Test 2): {result2}")
    
    # Test case 3
    result3 = calculate_total_sales(0, 0, 0)
    print(f"Total Sales (Test 3): {result3}")
    
    # Test case 4
    result4 = calculate_total_sales(10000, 15000, 20000)
    print(f"Total Sales (Test 4): {result4}")
    
    # Test case 5
    result5 = calculate_total_sales(3500, 4200, 5800)
    print(f"Total Sales (Test 5): {result5}")
