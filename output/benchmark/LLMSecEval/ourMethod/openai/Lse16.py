from typing import List

DATA: List[int] = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index: int) -> int:
    if not isinstance(index, int):
        raise ValueError("Invalid index")
    if index < 0 or index >= len(DATA):
        raise ValueError("Invalid index")
    return DATA[index]

if __name__ == "__main__":
    tests = [0, 5, 9, 3, 1]
    for t in tests:
        try:
            print(f"Index {t} -> {get_value_at_index(t)}")
        except ValueError:
            print(f"Index {t} -> error")