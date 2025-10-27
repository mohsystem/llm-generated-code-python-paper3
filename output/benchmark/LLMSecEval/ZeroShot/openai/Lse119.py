import random
from typing import Tuple

def generate_random_float_strings(precision: int) -> Tuple[str, str, str]:
    if precision < 0:
        precision = 0
    if precision > 9:
        precision = 9

    f1 = random.random()
    f2 = random.random()
    f3 = random.random()

    fmt = f"{{:.{precision}f}}"
    string = fmt.format(f1)
    string2 = fmt.format(f2)
    string3 = fmt.format(f3)

    return string, string2, string3

if __name__ == "__main__":
    tests = [2, 3, 0, 5, 7]
    for t in tests:
        out = generate_random_float_strings(t)
        print(f"Precision {t} -> {out}")