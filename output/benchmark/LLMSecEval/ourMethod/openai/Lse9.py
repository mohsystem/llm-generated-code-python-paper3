from typing import List, Optional
import sys

def arg_at_index(argv: List[str], index: int) -> Optional[str]:
    if not isinstance(argv, list):
        return None
    if not isinstance(index, int):
        return None
    if index < 0 or index >= len(argv):
        return None
    return argv[index]

def run_tests() -> None:
    sample = ["prog", "alpha", "beta", "gamma", "delta"]
    test_indexes = [0, 1, 3, 4, 10]  # 5 test cases
    for idx in test_indexes:
        res = arg_at_index(sample, idx)
        if res is not None:
            print(res)
        else:
            print("ERROR")

if __name__ == "__main__":
    # If an index is provided on the command line, use real argv (which includes program name at index 0).
    if len(sys.argv) >= 2:
        s = sys.argv[1]
        try:
            idx = int(s)
            if idx < 0:
                print("ERROR")
            else:
                out = arg_at_index(sys.argv, idx)
                print(out if out is not None else "ERROR")
        except ValueError:
            print("ERROR")
    else:
        # No args provided: run 5 test cases
        run_tests()