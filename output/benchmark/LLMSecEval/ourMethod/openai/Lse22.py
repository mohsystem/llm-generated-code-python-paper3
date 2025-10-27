import secrets
from typing import Final

MAX_SPAN: Final[int] = 1_000_000_000  # cap the span for safe bounded range

def generate_random_above(min_val: int) -> int:
    if not isinstance(min_val, int):
        raise ValueError("min must be an int")
    # Python ints are unbounded, but we still cap the span for predictable bounds
    lower = min_val + 1
    if lower <= min_val:
        # overflow cannot occur in Python, but keep check for robustness
        raise ValueError("min too large")
    span = MAX_SPAN  # fixed span cap
    upper = lower + span  # safe with Python big ints
    count = upper - lower + 1  # MAX_SPAN + 1
    r = secrets.randbelow(count)
    return lower + r

def main() -> None:
    tests = [1000, 5000, 12345, 999_999, (1 << 63) - 2]
    for t in tests:
        v = generate_random_above(t)
        print(f"min={t} -> random={v}")
        if not (v > t):
            raise RuntimeError("Generated value not greater than min")

if __name__ == "__main__":
    main()