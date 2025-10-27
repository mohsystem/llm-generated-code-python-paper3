DATA = (10, 20, 30, 40, 50, 60, 70, 80)

def get_value_at_index(index: int) -> int:
    if not isinstance(index, int):
        raise TypeError("index must be an integer")
    if index < 0 or index >= len(DATA):
        raise IndexError("index out of range")
    return DATA[index]

if __name__ == "__main__":
    tests = [0, 1, 2, 5, 7]
    for t in tests:
        try:
            print(f"Index {t} -> {get_value_at_index(t)}")
        except Exception as e:
            print(f"Index {t} -> error: {e}")