from typing import Tuple

def calculate(a: float, b: float, op: str) -> float:
    if not isinstance(op, str) or len(op) != 1:
        raise ValueError("Operator must be a single character: one of +, -, *, /.")
    if op == '+':
        return a + b
    if op == '-':
        return a - b
    if op == '*':
        return a * b
    if op == '/':
        if b == 0.0:
            raise ZeroDivisionError("Division by zero.")
        return a / b
    raise ValueError("Unsupported operator. Use one of +, -, *, /.")

if __name__ == "__main__":
    tests: Tuple[Tuple[float, float, str], ...] = (
        (10.0, 5.0, '+'),
        (10.0, 5.0, '-'),
        (10.0, 5.0, '*'),
        (10.0, 5.0, '/'),
        (10.0, 0.0, '/'),
    )
    for a, b, op in tests:
        try:
            result = calculate(a, b, op)
            print(f"{a} {op} {b} = {result}")
        except Exception as e:
            print(f"Operation {a} {op} {b} failed: {e}")