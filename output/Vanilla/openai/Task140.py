def calculate(a, b, op):
    if op == '+':
        return a + b
    if op == '-':
        return a - b
    if op == '*':
        return a * b
    if op == '/':
        return float('nan') if b == 0 else a / b
    return float('nan')

if __name__ == "__main__":
    print("3 + 5 =", calculate(3, 5, '+'))
    print("10 - 4 =", calculate(10, 4, '-'))
    print("7 * 6 =", calculate(7, 6, '*'))
    print("20 / 5 =", calculate(20, 5, '/'))
    print("7 / 0 =", calculate(7, 0, '/'))