from typing import Iterable, Tuple, Sequence, Union, List

Number = Union[int, bool]

def count_passengers(stops: Iterable[Sequence[Number]]) -> int:
    if stops is None:
        raise ValueError("stops cannot be None")
    count = 0
    for idx, pair in enumerate(stops):
        if pair is None or len(pair) < 2:
            raise ValueError("Each stop must be a pair of two non-negative integers")
        on, off = pair[0], pair[1]
        if not (isinstance(on, int) and isinstance(off, int)):
            raise TypeError("Values must be integers")
        if on < 0 or off < 0:
            raise ValueError("Values must be non-negative")
        if idx == 0 and off != 0:
            raise ValueError("At first stop, number of people getting off must be zero")
        after_board = count + on
        if off > after_board:
            raise ValueError("More people getting off than currently on the bus")
        count = after_board - off
    return count

if __name__ == "__main__":
    tests: List[List[Tuple[int, int]]] = [
        [(10, 0), (3, 5), (5, 8)],
        [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)],
        [(0, 0)],
        [(5, 0), (0, 0), (0, 0)],
        [(1_000_000_000, 0), (1_000_000_000, 0), (0, 1_000_000_000)],
    ]
    for t in tests:
        try:
            print(f"Stops: {t} -> Remaining: {count_passengers(t)}")
        except Exception as e:
            print(f"Stops: {t} -> Error: {e}")