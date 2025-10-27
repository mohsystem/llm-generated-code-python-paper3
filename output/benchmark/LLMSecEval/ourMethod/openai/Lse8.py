from typing import List

def value_at_index(argv: List[str]) -> str:
    if argv is None or len(argv) < 2:
        raise ValueError("insufficient arguments")
    idx_str = argv[1]
    if not isinstance(idx_str, str) or not idx_str.isdigit() or len(idx_str) > 10:
        raise ValueError("invalid index")
    idx = int(idx_str)
    if idx < 0 or idx >= len(argv):
        raise ValueError("index out of range")
    return argv[idx]

def main() -> None:
    tests: List[List[str]] = [
        ["prog", "0"],
        ["app", "2", "x", "y", "z"],
        ["cmd", "4", "A", "B", "C", "D", "E"],
        ["tool", "-1", "val"],
        ["t", "10", "a", "b"],
    ]
    for i, test in enumerate(tests, start=1):
        try:
            res = value_at_index(test)
            print(f"Test {i} -> {res}")
        except ValueError as e:
            print(f"Test {i} -> error: {e}")

if __name__ == "__main__":
    main()