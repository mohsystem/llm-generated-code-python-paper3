from typing import List

def get_value_at_index(arr: List[int], index: int) -> int:
    if arr is None:
        raise ValueError("Array reference is None.")
    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")
    if index < 0 or index >= len(arr):
        raise IndexError("Index out of bounds.")
    return arr[index]

def main():
    arr = [10, 20, 30, 40, 50]
    tests = [0, 2, 4, 5, -1]

    print(f"Array: {arr}")
    for idx in tests:
        try:
            value = get_value_at_index(arr, idx)
            print(f"Index {idx} -> {value}")
        except Exception as ex:
            print(f"Index {idx} -> Error: {ex}")

if __name__ == "__main__":
    main()