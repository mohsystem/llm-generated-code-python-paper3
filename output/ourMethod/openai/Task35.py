from typing import List, Sequence, Union

Pair = Union[Sequence[int], tuple]

def count_passengers(stops: List[Pair]) -> int:
    """
    Returns final number of passengers or -1 on invalid input.
    """
    if stops is None:
        return 0
    current = 0
    for i, pair in enumerate(stops):
        if pair is None or len(pair) < 2:
            return -1
        on, off = pair[0], pair[1]
        if not isinstance(on, int) or not isinstance(off, int):
            return -1
        if on < 0 or off < 0:
            return -1
        current += on
        if off > current:
            return -1
        current -= off
    if current < 0:
        return -1
    return current

def main() -> None:
    tc1 = [(10, 0), (3, 5), (5, 8)]  # expected 5
    tc2 = [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)]  # expected 17
    tc3 = [(0, 0)]  # expected 0
    tc4 = [(5, 0), (0, 0), (0, 0)]  # expected 5
    tc5 = [(1_000_000, 0), (0, 999_999), (0, 0), (0, 1)]  # expected 0

    print(count_passengers(tc1))
    print(count_passengers(tc2))
    print(count_passengers(tc3))
    print(count_passengers(tc4))
    print(count_passengers(tc5))

if __name__ == "__main__":
    main()