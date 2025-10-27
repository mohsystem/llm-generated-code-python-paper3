from typing import List
import sys

def getValueFromArray(arr: List[int], size: int, index: int) -> int:
    if arr is None:
        raise ValueError("Array is None")
    if size < 0 or size > len(arr):
        raise ValueError("Invalid size")
    if index < 0 or index >= size:
        raise IndexError("Invalid index")
    return arr[index]

def main() -> None:
    id_sequence: List[int] = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3]
    size: int = len(id_sequence)

    # 5 test cases
    test_indices = [0, 3, 9, 5, 7]
    for idx in test_indices:
        try:
            val = getValueFromArray(id_sequence, size, idx)
            print(f"Test index {idx} => {val}")
        except Exception:
            print(f"Test index {idx} => ERROR")

    # Read one integer index from stdin and return value as exit code
    try:
        line = sys.stdin.readline(64)
        if not line:
            print("ERROR", file=sys.stderr)
            sys.exit(1)
        line = line.strip()
        if len(line) == 0 or len(line) > 32:
            print("ERROR", file=sys.stderr)
            sys.exit(1)
        idx_val = int(line, 10)
        if idx_val < 0 or idx_val >= size:
            print("ERROR", file=sys.stderr)
            sys.exit(1)
        result = getValueFromArray(id_sequence, size, idx_val)
        sys.exit(result)
    except Exception:
        print("ERROR", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()