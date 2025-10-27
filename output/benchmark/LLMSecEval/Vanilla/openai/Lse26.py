def getMonthlySales(i, sales):
    return sales[i]

def total_first_quarter_sales(sales):
    s = 0
    for i in range(3):
        s += getMonthlySales(i, sales)
    return s

if __name__ == "__main__":
    tests = [
        [100, 200, 300],
        [0, 0, 0, 0],
        [5, 10, 15, 20],
        [1000, -50, 25, 0],
        [7, 8, 9, 10, 11]
    ]
    for idx, arr in enumerate(tests, 1):
        print(f"Test {idx}: {total_first_quarter_sales(arr)}")