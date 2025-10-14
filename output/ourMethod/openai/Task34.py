from typing import List

def narcissistic(n: int) -> bool:
    if not isinstance(n, int) or n <= 0:
        return False
    s = str(n)
    power = len(s)
    total = sum((int(ch) ** power) for ch in s)
    return total == n

if __name__ == "__main__":
    tests: List[int] = [1, 153, 370, 1652, 9474]
    for t in tests:
        print(f"n={t} -> {narcissistic(t)}")