from dataclasses import dataclass
from secrets import randbelow

@dataclass
class Result:
    first: int
    second: int
    difference: int

def generate_and_diff() -> Result:
    first = 10 + randbelow(991)   # 10..1000 inclusive
    second = 10 + randbelow(991)  # 10..1000 inclusive
    difference = first - second
    return Result(first, second, difference)

def main() -> None:
    for i in range(1, 6):
        r = generate_and_diff()
        print(f"Test {i}: First: {r.first}, Second: {r.second}, Difference (first - second): {r.difference}")

if __name__ == "__main__":
    main()