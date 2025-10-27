from typing import List

def get_value_at_index(index: int, arr: List[int]) -> int:
    if not isinstance(arr, list):
        raise ValueError("invalid input")
    if not isinstance(index, int):
        raise ValueError("invalid input")
    if index < 0 or index >= len(arr):
        raise ValueError("invalid input")
    return arr[index]

def main() -> None:
    arr: List[int] = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    tests: List[int] = [0, 5, 9, 3, 10]  # 10 is invalid to demonstrate error handling
    for t in tests:
        try:
            value = get_value_at_index(t, arr)
            print(f"index {t} -> {value}")
        except ValueError:
            print(f"index {t} -> error")

if __name__ == "__main__":
    main()