import secrets
from typing import Tuple, List

def generate_random_float_strings(precision: int) -> Tuple[str, str, str]:
    if not isinstance(precision, int):
        raise ValueError("Invalid precision")
    if precision < 0 or precision > 9:
        raise ValueError("Invalid precision")
    rng = secrets.SystemRandom()
    v1 = rng.random()
    v2 = rng.random()
    v3 = rng.random()
    fmt = "%." + str(precision) + "f"
    string = fmt % v1
    string2 = fmt % v2
    string3 = fmt % v3
    return string, string2, string3

if __name__ == "__main__":
    tests: List[int] = [0, 2, 4, 6, 9]
    for p in tests:
        s1, s2, s3 = generate_random_float_strings(p)
        print(f"Precision {p} -> string: {s1}, string2: {s2}, string3: {s3}")