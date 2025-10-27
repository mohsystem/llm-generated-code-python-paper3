DATA = (11, 22, 33, 44, 55, 66, 77, 88, 99, 110)

def get_value_at_index(index: int) -> int:
    if not isinstance(index, int):
        raise TypeError("index must be an integer")
    if index < 0 or index >= len(DATA):
        raise IndexError("index out of bounds")
    return DATA[index]

if __name__ == "__main__":
    tests = [0, 5, 9, 3, 7]
    for t in tests:
        try:
            v = get_value_at_index(t)
            print(f"Index {t} -> {v}")
        except Exception as e:
            print(f"Index {t} -> error: {e}")