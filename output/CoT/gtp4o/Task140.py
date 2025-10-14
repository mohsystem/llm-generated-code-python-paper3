# Chain-of-Through process:
# 1) Problem understanding: Provide a function to perform +, -, *, / on two numbers based on operator input.
# 2) Security requirements: Avoid unsafe input handling; no eval; handle division by zero; return NaN on invalid cases.
# 3) Secure coding generation: Validate operator; use float math; no side effects.
# 4) Code review: Ensure consistent return type and safe fallback.
# 5) Secure code output: Deterministic behavior with 5 test cases.

from math import nan

def calculate(a: float, b: float, op: str) -> float:
    if not isinstance(op, str) or len(op) != 1:
        return nan
    if op == '+':
        return a + b
    elif op == '-':
        return a - b
    elif op == '*':
        return a * b
    elif op == '/':
        return nan if b == 0.0 else a / b
    else:
        return nan

if __name__ == "__main__":
    # 5 test cases
    tests = [
        (10.0, 5.0, '+'),
        (10.0, 5.0, '-'),
        (10.0, 5.0, '*'),
        (10.0, 0.0, '/'),
        (10.0, 5.0, '%'),  # invalid operator
    ]
    for i, (a, b, op) in enumerate(tests, 1):
        print(f"Test {i}: {a} {op} {b} = {calculate(a, b, op)}")