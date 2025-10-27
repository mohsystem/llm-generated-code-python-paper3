from typing import List

def get_monthly_sales(sales: List[int], i: int) -> int:
    if sales is None:
        raise ValueError("Sales list cannot be None")
    if i < 0 or i >= len(sales):
        raise ValueError("Index out of range for sales list")
    return sales[i]

def total_first_quarter_sales(sales: List[int]) -> int:
    if sales is None or len(sales) < 3:
        raise ValueError("Sales list must contain at least 3 elements")
    total = 0
    for i in range(3):
        total += get_monthly_sales(sales, i)
    return total

def main():
    tests = [
        [100, 200, 300, 400, 500],        # Expected: 600
        [0, 0, 0],                        # Expected: 0
        [12345, 67890, 11111],            # Expected: 91346
        [2**63 - 1, 0, 0, 5],             # Python int handles big ints; Expected: 2**63 - 1
        [-10, 20, -5, 0, 1000]            # Expected: 5
    ]
    for idx, test in enumerate(tests, 1):
        try:
            result = total_first_quarter_sales(test)
            print(f"Test {idx} {test[:3]} => {result}")
        except Exception as e:
            print(f"Test {idx} error: {e}")

if __name__ == "__main__":
    main()