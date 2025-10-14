from typing import List

MAX_FLOORS: int = 1000

def build_tower(floors: int) -> List[str]:
    if not isinstance(floors, int):
        raise TypeError("floors must be an integer")
    if floors < 1 or floors > MAX_FLOORS:
        raise ValueError(f"floors must be between 1 and {MAX_FLOORS}")
    width = 2 * floors - 1
    result: List[str] = []
    for i in range(1, floors + 1):
        spaces = floors - i
        stars = 2 * i - 1
        row = (" " * spaces) + ("*" * stars) + (" " * spaces)
        # Ensure exact width to avoid any surprises
        if len(row) != width:
            raise ValueError("Internal error: row width mismatch")
        result.append(row)
    return result

def _print_tower(tower: List[str]) -> None:
    print("[")
    for idx, row in enumerate(tower):
        comma = "," if idx + 1 < len(tower) else ""
        print(f'  "{row}"{comma}')
    print("]")

if __name__ == "__main__":
    tests = [1, 3, 6, 2, 0]
    for t in tests:
        print(f"Test floors={t}")
        try:
            tower = build_tower(t)
            _print_tower(tower)
        except Exception as e:
            print(f"Error: {e}")
        print()