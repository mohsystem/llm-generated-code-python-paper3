from typing import Any, List

def filter_list(items: List[Any]) -> List[int]:
    if items is None:
        return []
    # Exclude bools (subclass of int) and negative integers
    return [x for x in items if isinstance(x, int) and not isinstance(x, bool) and x >= 0]

def _print(lst: List[int]) -> None:
    print(lst)

if __name__ == "__main__":
    # Test case 1
    t1 = [1, 2, "a", "b"]
    _print(filter_list(t1))  # [1, 2]

    # Test case 2
    t2 = [1, "a", "b", 0, 15]
    _print(filter_list(t2))  # [1, 0, 15]

    # Test case 3
    t3 = [1, 2, "a", "b", "aasf", "1", "123", 123]
    _print(filter_list(t3))  # [1, 2, 123]

    # Test case 4 (includes negative integer and booleans)
    t4 = ["hello", -1, 3, "4", 0, True, False]
    _print(filter_list(t4))  # [3, 0]

    # Test case 5 (empty list)
    t5 = []
    _print(filter_list(t5))  # []