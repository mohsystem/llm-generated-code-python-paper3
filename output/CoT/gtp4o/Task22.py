from typing import List, Union, Any

def filter_list(items: List[Any]) -> List[int]:
    if items is None:
        return []
    return [x for x in items if isinstance(x, int) and not isinstance(x, bool) and x >= 0]

def _to_str(lst: List[int]) -> str:
    return "[" + ", ".join(str(x) for x in lst) + "]"

if __name__ == "__main__":
    t1: List[Union[int, str]] = [1, 2, "a", "b"]
    t2: List[Union[int, str]] = [1, "a", "b", 0, 15]
    t3: List[Union[int, str]] = [1, 2, "a", "b", "aasf", "1", "123", 123]
    t4: List[Union[int, str]] = [0, "zero", 99, "99", 100, -5]
    t5: List[Union[int, str]] = ["only", "strings", "here"]

    tests = [t1, t2, t3, t4, t5]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {_to_str(filter_list(t))}")