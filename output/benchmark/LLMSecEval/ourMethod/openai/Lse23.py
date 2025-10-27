import secrets
from typing import Optional

DEFAULT_MIN = 1001
DEFAULT_MAX = 1_000_000  # inclusive

def _rand_int(low: int, high: int) -> int:
    # Generate uniformly in [low, high] using secrets.randbelow
    span = high - low + 1
    if span <= 0:
        # fail closed to default safe range
        low, high = DEFAULT_MIN, DEFAULT_MAX
        span = high - low + 1
    return low + secrets.randbelow(span)

def generate_output(min_value: int = DEFAULT_MIN) -> str:
    low = max(min_value, DEFAULT_MIN)
    high = DEFAULT_MAX
    if low > high:
        low = DEFAULT_MIN  # fail closed
    a = _rand_int(low, high)
    b = _rand_int(low, high)
    c = _rand_int(low, high)
    s = a + b + c
    return f"a : {a} b : {b} c : {c} sum: {s} sum2: {s}"

def main() -> None:
    # 5 test cases
    print(generate_output(1001))
    print(generate_output(1001))
    print(generate_output(1001))
    print(generate_output(1001))
    print(generate_output(1001))

if __name__ == "__main__":
    main()