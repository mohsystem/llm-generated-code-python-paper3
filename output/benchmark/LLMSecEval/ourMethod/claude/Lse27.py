
import sys
import math

def calculate_total_sales(month1, month2, month3):
    """\n    Calculate total sales from three monthly sales values.\n    \n    Args:\n        month1: Sales for first month\n        month2: Sales for second month\n        month3: Sales for third month\n    \n    Returns:\n        Total sales across all three months\n    \n    Raises:\n        ValueError: If any input is negative or not a valid number\n        TypeError: If inputs are not numeric types\n    """
    # Validate input types
    if not all(isinstance(x, (int, float)) for x in [month1, month2, month3]):
        raise TypeError("All sales values must be numeric")
    
    # Validate inputs are non-negative (sales cannot be negative)
    if month1 < 0 or month2 < 0 or month3 < 0:
        raise ValueError("Sales values cannot be negative")
    
    # Check for NaN or infinity
    if any(math.isnan(x) or math.isinf(x) for x in [month1, month2, month3]):
        raise ValueError("Sales values must be valid finite numbers")
    
    # Initialize totalSales to 0.0
    total_sales = 0.0
    
    # Add each month's sales to total_sales
    total_sales += month1
    total_sales += month2
    total_sales += month3
    
    # Verify result is valid
    if math.isnan(total_sales) or math.isinf(total_sales):
        raise ArithmeticError("Total sales calculation resulted in invalid value")
    
    return total_sales

def main():
    """Main function with test cases"""
    
    # Test case 1: Normal positive values
    try:
        result1 = calculate_total_sales(1000.50, 1500.75, 2000.25)
        print(f"Test 1 - Total sales: {result1}")
    except Exception as e:
        print(f"Test 1 failed: {e}", file=sys.stderr)
    
    # Test case 2: Zero values
    try:
        result2 = calculate_total_sales(0.0, 0.0, 0.0)
        print(f"Test 2 - Total sales: {result2}")
    except Exception as e:
        print(f"Test 2 failed: {e}", file=sys.stderr)
    
    # Test case 3: Large values
    try:
        result3 = calculate_total_sales(50000.99, 75000.50, 100000.01)
        print(f"Test 3 - Total sales: {result3}")
    except Exception as e:
        print(f"Test 3 failed: {e}", file=sys.stderr)
    
    # Test case 4: Negative value (should fail)
    try:
        result4 = calculate_total_sales(1000.0, -500.0, 2000.0)
        print(f"Test 4 - Total sales: {result4}")
    except Exception as e:
        print(f"Test 4 failed (expected): {e}", file=sys.stderr)
    
    # Test case 5: Mixed decimal values
    try:
        result5 = calculate_total_sales(123.45, 678.90, 234.56)
        print(f"Test 5 - Total sales: {result5}")
    except Exception as e:
        print(f"Test 5 failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
