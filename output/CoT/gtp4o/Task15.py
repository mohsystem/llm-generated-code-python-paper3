from typing import List

def build_tower(n: int) -> List[str]:
    if n <= 0:
        return []
    width = 2 * n - 1
    result: List[str] = []
    for i in range(1, n + 1):
        stars = 2 * i - 1
        spaces = (width - stars) // 2
        result.append(" " * spaces + "*" * stars + " " * spaces)
    return result

def _print_tower(tower: List[str]) -> None:
    print("[")
    for idx, line in enumerate(tower):
        sep = "," if idx + 1 < len(tower) else ""
        print(f'  "{line}"{sep}')
    print("]")

def main():
    tests = [1, 2, 3, 5, 6]
    for t in tests:
        print(f"Floors: {t}")
        tower = build_tower(t)
        _print_tower(tower)
        print()

if __name__ == "__main__":
    main()