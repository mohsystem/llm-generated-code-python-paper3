from typing import List

# Fixed id_sequence array
ID_SEQUENCE: List[int] = [101, 203, 304, 405, 506, 607, 708, 809, 910, 1001]

def get_id_at_index(index: int) -> int:
    """
    Returns the value at the given index in ID_SEQUENCE.
    Raises IndexError for invalid indices and TypeError for non-integer input.
    """
    if not isinstance(index, int):
        raise TypeError("Invalid input.")
    if index < 0 or index >= len(ID_SEQUENCE):
        raise IndexError("Invalid index.")
    return ID_SEQUENCE[index]

def main() -> None:
    try:
        raw = input(f"Enter an index (0..{len(ID_SEQUENCE)-1}): ")
        index = int(raw.strip())
        value = get_id_at_index(index)
        print(f"Value at index {index}: {value}")
    except ValueError:
        print("Invalid input.")
    except IndexError:
        print("Invalid index.")
    except Exception:
        print("I/O error.")

    # 5 Test cases
    print("Running test cases:")
    tests = [0, 3, 9, -1, 10]
    for idx in tests:
        try:
            val = get_id_at_index(idx)
            print(f"Index {idx} => {val}")
        except Exception:
            print(f"Index {idx} => error")

if __name__ == "__main__":
    main()