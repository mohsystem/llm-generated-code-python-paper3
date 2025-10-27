from typing import List, Optional

def get_value_at_index_from_args(argv: List[str]) -> Optional[str]:
    if argv is None or len(argv) < 2:
        return None
    try:
        idx = int(argv[1])
    except (ValueError, TypeError):
        return None
    if idx < 0 or idx >= len(argv):
        return None
    return argv[idx]

if __name__ == "__main__":
    # 5 test cases
    tests = [
        ["prog", "2", "a", "b", "c"],   # expects "a"
        ["prog", "0"],                  # expects "prog"
        ["prog", "10", "x"],            # expects None (out of range)
        ["prog", "-1", "x"],            # expects None (negative index)
        ["prog", "notanint", "x"],      # expects None (parse error)
    ]
    for t in tests:
        print(get_value_at_index_from_args(t))