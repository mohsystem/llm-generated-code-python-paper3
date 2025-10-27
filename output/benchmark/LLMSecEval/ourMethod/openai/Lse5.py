from typing import List, Optional
import sys

def get_element_at(arr: List[str], idx: int) -> str:
    if arr is None:
        raise ValueError("Invalid input")
    if idx < 0 or idx >= len(arr):
        raise IndexError("Invalid index")
    return arr[idx]

def safe_parse_index(s: str) -> Optional[int]:
    if s is None:
        return None
    s = s.strip()
    if not s or len(s) > 32:  # guard against excessively long inputs
        return None
    # Strict base-10 parse
    try:
        # Disallow underscores and spaces within the number
        if any(ch in s for ch in "_ \t\n\r\x0b\x0c"):
            return None
        return int(s, 10)
    except ValueError:
        return None

def create_elements() -> List[str]:
    return ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]

def main() -> None:
    elements = create_elements()

    if len(sys.argv) >= 2:
        idx = safe_parse_index(sys.argv[1])
        if idx is None:
            print("Invalid input")
            return
        try:
            print(get_element_at(elements, idx))
        except (IndexError, ValueError):
            print("Invalid index")
        return

    # 5 test cases
    test_indices = [0, 2, 5, -1, 6]
    for t in test_indices:
        try:
            val = get_element_at(elements, t)
            print(f"Index {t} -> {val}")
        except (IndexError, ValueError):
            print(f"Index {t} -> Invalid index")

if __name__ == "__main__":
    main()