from typing import Iterable, Sequence, Union, List, Tuple

Pair = Union[Sequence[int], Tuple[int, int], List[int]]


def count_passengers(stops: Iterable[Pair]) -> int:
    """
    Returns the number of people remaining on the bus after the last stop.
    Returns -1 for invalid input (e.g., negative values, wrong pair sizes, or occupancy going negative).
    """
    if stops is None:
        return -1

    occupancy: int = 0
    for pair in stops:
        if pair is None or not isinstance(pair, (list, tuple)) or len(pair) != 2:
            return -1
        on, off = pair[0], pair[1]
        if not isinstance(on, int) or not isinstance(off, int):
            return -1
        if on < 0 or off < 0:
            return -1
        next_occ = occupancy + on - off
        if next_occ < 0:
            return -1
        occupancy = next_occ

    # Python ints are unbounded, but align with typical int return semantics; still fine to return occupancy
    return occupancy


if __name__ == "__main__":
    t1 = [(10, 0), (3, 5), (5, 8)]  # expected 5
    t2 = [(3, 0), (9, 1), (4, 10), (12, 2)]  # expected 15
    t3 = [(0, 0)]  # expected 0
    t4 = [(5, 0), (0, 0), (0, 0)]  # expected 5
    t5 = [(5, 0), (2, 10)]  # invalid -> expected -1

    print(count_passengers(t1))
    print(count_passengers(t2))
    print(count_passengers(t3))
    print(count_passengers(t4))
    print(count_passengers(t5))