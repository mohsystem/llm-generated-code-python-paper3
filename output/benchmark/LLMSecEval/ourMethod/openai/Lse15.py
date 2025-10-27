from typing import Optional, List, TextIO
import sys

def get_value_at_index(id_sequence: List[int], index: int) -> Optional[int]:
    if not isinstance(id_sequence, list):
        return None
    if not isinstance(index, int):
        return None
    if index < 0 or index >= len(id_sequence):
        return None
    return id_sequence[index]

def prompt_and_get_value(id_sequence: List[int], reader: TextIO = sys.stdin) -> Optional[int]:
    if id_sequence is None or reader is None:
        return None
    print(f"Enter index (0..{len(id_sequence)-1}): ", end="", flush=True)
    line = reader.readline()
    if not line:
        print("No input.")
        return None
    s = line.strip()
    if len(s) == 0 or len(s) > 18:
        print("Invalid input.")
        return None
    try:
        idx = int(s, 10)
    except ValueError:
        print("Invalid input.")
        return None
    val = get_value_at_index(id_sequence, idx)
    if val is None:
        print("Invalid index.")
        return None
    return val

def main() -> None:
    id_sequence = [42, 7, 13, 99, 5, 81, 23, 64, 12, 30]
    for _ in range(5):
        result = prompt_and_get_value(id_sequence, sys.stdin)
        if result is not None:
            print(f"Value: {result}")
        else:
            print("No value returned.")

if __name__ == "__main__":
    main()