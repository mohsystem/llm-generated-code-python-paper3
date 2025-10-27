from typing import List

ID_SEQUENCE: List[int] = [7, 13, 21, 34, 55, 89, 144, 233, 377, 610]

def get_value_at_index(index: int) -> int:
    if not isinstance(index, int):
        raise TypeError("invalid input")
    if index < 0 or index >= len(ID_SEQUENCE):
        raise IndexError("invalid index")
    return ID_SEQUENCE[index]

def main() -> None:
    try:
        raw = input(f"Enter an index (0..{len(ID_SEQUENCE)-1}): ")
    except EOFError:
        print("Error: no input.", flush=True)
    else:
        s = (raw or "").strip()
        if len(s) == 0 or len(s) > 64:
            print("Error: invalid input.", flush=True)
        else:
            try:
                idx = int(s, 10)
            except ValueError:
                print("Error: invalid input.", flush=True)
            else:
                if idx < 0 or idx >= len(ID_SEQUENCE):
                    print("Error: invalid index.", flush=True)
                else:
                    try:
                        value = get_value_at_index(idx)
                        print(f"Value at index {idx} = {value}", flush=True)
                    except Exception:
                        print("Error: invalid index.", flush=True)

    # 5 test cases
    tests = [0, len(ID_SEQUENCE)-1, 2, 5, 7]
    for t in tests:
        try:
            v = get_value_at_index(t)
            print(f"Test index {t} -> {v}")
        except Exception:
            print(f"Test index {t} -> error")

if __name__ == "__main__":
    main()