from typing import Tuple, List

def get_sum(a: int, b: int) -> int:
    start = min(a, b)
    end = max(a, b)
    n = (end - start) + 1  # number of terms
    sum_pair = start + end  # first + last
    if n % 2 == 0:
        return (n // 2) * sum_pair
    else:
        return n * (sum_pair // 2)

if __name__ == "__main__":
    tests: List[Tuple[int, int]] = [
        (1, 0),
        (1, 2),
        (0, 1),
        (1, 1),
        (-1, 2),
    ]
    for a, b in tests:
        print(get_sum(a, b))