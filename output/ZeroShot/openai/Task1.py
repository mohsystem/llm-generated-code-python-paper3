from typing import List, Tuple

def people_on_bus(stops: List[Tuple[int, int]]) -> int:
    if stops is None:
        raise ValueError("stops cannot be None")
    current = 0
    for i, pair in enumerate(stops):
        if pair is None or not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("Each stop must be a pair of two integers")
        on, off = pair
        if not isinstance(on, int) or not isinstance(off, int):
            raise ValueError("Counts must be integers")
        if on < 0 or off < 0:
            raise ValueError("Counts cannot be negative")
        if i == 0 and off != 0:
            raise ValueError("First stop must have 0 getting off")
        if off > current + on:
            raise ValueError("More people getting off than available on the bus")
        current = current + on - off
    if current < 0:
        raise RuntimeError("Resulting count cannot be negative")
    return current

if __name__ == "__main__":
    case1 = [(10, 0), (3, 5), (5, 8)]                        # Expected: 5
    case2 = [(3, 0), (9, 1), (4, 10), (12, 2), (6, 1), (7, 10)]  # Expected: 17
    case3 = [(0, 0)]                                         # Expected: 0
    case4 = [(20, 0), (0, 10), (5, 5)]                       # Expected: 10
    case5 = [(5, 0), (0, 5), (5, 0), (0, 5)]                 # Expected: 0

    print(people_on_bus(case1))
    print(people_on_bus(case2))
    print(people_on_bus(case3))
    print(people_on_bus(case4))
    print(people_on_bus(case5))