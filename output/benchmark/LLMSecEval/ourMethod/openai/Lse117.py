import secrets
from typing import List, Tuple

def a(x: float) -> str:
    return f"{x:.6f}"

def generate_n_random_float_strings(n: int) -> List[str]:
    if not isinstance(n, int) or n <= 0 or n > 1000:
        raise ValueError("invalid input")
    rng = secrets.SystemRandom()
    return [a(rng.random()) for _ in range(n)]

def main() -> None:
    # Core requirement demonstration
    trio: List[str] = generate_n_random_float_strings(3)
    str_a, str_b, str_c = trio[0], trio[1], trio[2]
    print("Test 1:", [str_a, str_b, str_c])

    # Additional 4 test cases
    for i in range(2, 6):
        print(f"Test {i}:", generate_n_random_float_strings(3))

if __name__ == "__main__":
    main()