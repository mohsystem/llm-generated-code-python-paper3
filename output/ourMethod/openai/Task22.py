from typing import Any, List

def filter_list(items: List[Any]) -> List[int]:
    if not isinstance(items, list):
        raise ValueError("Input must be a list.")
    result: List[int] = []
    for x in items:
        if isinstance(x, bool):
            # Booleans are subclasses of int in Python; reject explicitly.
            raise ValueError("Booleans are not allowed.")
        if isinstance(x, int):
            if x < 0:
                raise ValueError(f"Negative integers are not allowed: {x}")
            result.append(x)
        elif isinstance(x, str):
            # skip strings
            continue
        else:
            raise ValueError(f"Unsupported element type: {type(x).__name__}")
    return result

def main() -> None:
    tests = [
        [1, 2, "a", "b"],
        [1, "a", "b", 0, 15],
        [1, 2, "a", "b", "aasf", "1", "123", 123],
        ["hello", "world"],
        [0, 99, "x", "y", 42],
    ]
    for i, t in enumerate(tests, 1):
        res = filter_list(t)
        print(f"Test {i}: {res}")

if __name__ == "__main__":
    main()