
import secrets
from typing import Tuple

def get_monthly_sales() -> int:
    """\n    Returns a random sales value between 0 and 100000 (inclusive).\n    Uses secrets module for cryptographically secure random number generation.\n    \n    Returns:\n        int: Random sales value in range [0, 100000]\n    """
    # secrets.randbelow(n) returns [0, n), so we use 100001 to include 100000
    return secrets.randbelow(100001)

def calculate_quarterly_sales() -> Tuple[int, int, int, int]:
    """\n    Calculates quarterly sales by calling get_monthly_sales 12 times\n    and aggregating results into 4 quarters.\n    \n    Returns:\n        Tuple of 4 integers representing Q1, Q2, Q3, Q4 sales\n    """
    # Initialize quarterly sales - explicit initialization
    q1: int = 0
    q2: int = 0
    q3: int = 0
    q4: int = 0
    
    # Quarter 1: January, February, March (months 0-2)
    for _ in range(3):
        sales = get_monthly_sales()
        # Python handles large integers automatically, but we check for reasonable bounds
        if q1 > 10**15:  # Sanity check to prevent excessive values
            raise OverflowError("Q1 sales exceeded reasonable bounds")
        q1 += sales
    
    # Quarter 2: April, May, June (months 3-5)
    for _ in range(3):
        sales = get_monthly_sales()
        if q2 > 10**15:
            raise OverflowError("Q2 sales exceeded reasonable bounds")
        q2 += sales
    
    # Quarter 3: July, August, September (months 6-8)
    for _ in range(3):
        sales = get_monthly_sales()
        if q3 > 10**15:
            raise OverflowError("Q3 sales exceeded reasonable bounds")
        q3 += sales
    
    # Quarter 4: October, November, December (months 9-11)
    for _ in range(3):
        sales = get_monthly_sales()
        if q4 > 10**15:
            raise OverflowError("Q4 sales exceeded reasonable bounds")
        q4 += sales
    
    # Print results using constant format strings for security
    print(f"Q1 Sales: {q1}")
    print(f"Q2 Sales: {q2}")
    print(f"Q3 Sales: {q3}")
    print(f"Q4 Sales: {q4}")
    
    return q1, q2, q3, q4

def main() -> None:
    """Main function with 5 test cases"""
    # Test case 1
    print("Test Case 1:")
    calculate_quarterly_sales()
    print()
    
    # Test case 2
    print("Test Case 2:")
    calculate_quarterly_sales()
    print()
    
    # Test case 3
    print("Test Case 3:")
    calculate_quarterly_sales()
    print()
    
    # Test case 4
    print("Test Case 4:")
    calculate_quarterly_sales()
    print()
    
    # Test case 5
    print("Test Case 5:")
    calculate_quarterly_sales()

if __name__ == "__main__":
    main()
