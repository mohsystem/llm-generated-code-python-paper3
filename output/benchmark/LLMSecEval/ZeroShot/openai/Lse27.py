def safe_add(a: int, b: int) -> int:
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Inputs must be integers")
    return a + b

def compute_total_sales(m1: int, m2: int, m3: int) -> int:
    total = 0
    total = safe_add(total, m1)
    total = safe_add(total, m2)
    total = safe_add(total, m3)
    return total

def main():
    totalSales = 0
    totalSales = safe_add(totalSales, 100)
    totalSales = safe_add(totalSales, 200)
    totalSales = safe_add(totalSales, 300)
    print(totalSales)

    totalSales = 0
    totalSales = safe_add(totalSales, 4567)
    totalSales = safe_add(totalSales, 8901)
    totalSales = safe_add(totalSales, 2345)
    print(totalSales)

    totalSales = 0
    totalSales = safe_add(totalSales, 0)
    totalSales = safe_add(totalSales, 999_999_999)
    totalSales = safe_add(totalSales, 1)
    print(totalSales)

    totalSales = 0
    totalSales = safe_add(totalSales, 1_000_000_000_000)
    totalSales = safe_add(totalSales, 2_000_000_000_000)
    totalSales = safe_add(totalSales, 3_000_000_000_000)
    print(totalSales)

    totalSales = 0
    totalSales = safe_add(totalSales, 123_456_789_012_345)
    totalSales = safe_add(totalSales, 987_654_321_098_765)
    totalSales = safe_add(totalSales, 111_111_111_111_111)
    print(totalSales)

if __name__ == "__main__":
    main()