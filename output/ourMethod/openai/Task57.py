from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class FactorialResult:
    success: bool
    value: int
    error: str

def factorial(n: int) -> FactorialResult:
    if not isinstance(n, int):
        return FactorialResult(False, 0, "Input must be an integer.")
    if n < 0:
        return FactorialResult(False, 0, "Input must be a non-negative integer.")
    # For cross-language consistency with 64-bit limits
    if n > 20:
        return FactorialResult(False, 0, "Input too large; maximum supported is 20 for 64-bit.")
    acc = 1
    for i in range(2, n + 1):
        acc *= i
    return FactorialResult(True, acc, "")

def main() -> None:
    tests: List[int] = [0, 1, 5, 20, 21]
    for n in tests:
        res = factorial(n)
        if res.success:
            print(f"factorial({n}) = {res.value}")
        else:
            print(f"factorial({n}) error: {res.error}")

if __name__ == "__main__":
    main()