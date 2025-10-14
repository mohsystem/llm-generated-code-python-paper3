from dataclasses import dataclass
from typing import Tuple

@dataclass(frozen=True)
class CalcResult:
    ok: bool
    value: float
    error: str

def calculate(a: float, b: float, op: str) -> CalcResult:
    if not isinstance(op, str) or len(op) != 1:
        return CalcResult(False, 0.0, "Invalid operator")
    if op == '+':
        return CalcResult(True, a + b, "")
    if op == '-':
        return CalcResult(True, a - b, "")
    if op == '*':
        return CalcResult(True, a * b, "")
    if op == '/':
        if b == 0.0:
            return CalcResult(False, 0.0, "Division by zero")
        return CalcResult(True, a / b, "")
    return CalcResult(False, 0.0, "Invalid operator")

def _print_result(a: float, b: float, op: str, res: CalcResult) -> None:
    if res.ok:
        print(f"Input: {a:.6f} {op} {b:.6f} => Result: {res.value:.6f}")
    else:
        print(f"Input: {a:.6f} {op} {b:.6f} => Error: {res.error}")

def main() -> None:
    tests: Tuple[Tuple[float, float, str], ...] = (
        (3.0, 5.0, '+'),
        (10.0, 3.0, '-'),
        (-2.5, 4.0, '*'),
        (7.0, 2.0, '/'),
        (5.0, 0.0, '/'),
    )
    for a, b, op in tests:
        res = calculate(a, b, op)
        _print_result(a, b, op, res)

if __name__ == "__main__":
    main()