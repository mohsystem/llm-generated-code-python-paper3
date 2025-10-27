# Immutable ID sequence
_ID_SEQUENCE = (101, 202, 303, 404, 505)

def get_id_at_index(index: int) -> int:
    """Return the value at the given index, or -1 if index is invalid."""
    if not isinstance(index, int):
        return -1
    if index < 0 or index >= len(_ID_SEQUENCE):
        return -1
    return _ID_SEQUENCE[index]

if __name__ == "__main__":
    tests = [0, 4, 2, -1, 10]  # 5 test cases
    for idx in tests:
        print(get_id_at_index(idx))