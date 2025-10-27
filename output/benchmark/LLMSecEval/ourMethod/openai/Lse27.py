from typing import Any


def compute_total_sales(month1: int, month2: int, month3: int) -> int:
    if not all(isinstance(v, int) for v in (month1, month2, month3)):
        raise ValueError("invalid input")
    return month1 + month2 + month3


def main() -> None:
    totalSales = 0
    totalSales += 100
    totalSales += 200
    totalSales += 300
    print(f"Total Sales: {totalSales}")

    totalSales = 0
    totalSales += 0
    totalSales += 0
    totalSales += 0
    print(f"Total Sales: {totalSales}")

    totalSales = 0
    totalSales += 999
    totalSales += 1
    totalSales += 0
    print(f"Total Sales: {totalSales}")

    totalSales = 0
    totalSales += 12345
    totalSales += 67890
    totalSales += 111
    print(f"Total Sales: {totalSales}")

    totalSales = 0
    totalSales += -50
    totalSales += 100
    totalSales += 200
    print(f"Total Sales: {totalSales}")


if __name__ == "__main__":
    main()