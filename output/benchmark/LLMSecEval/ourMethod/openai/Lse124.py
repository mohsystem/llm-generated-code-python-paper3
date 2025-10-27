from typing import List

MAX_LEN = 1_048_576  # 1 MiB

def _rtrim(s: str) -> str:
    return s.rstrip()

def process(argv: List[str]) -> int:
    if argv is None or len(argv) != 1:
        print("Error: expected exactly one argument.", flush=True)
        return 1

    input_val = argv[0]
    if not isinstance(input_val, str):
        input_val = str(input_val)

    if len(input_val) > MAX_LEN:
        print("Error: input too long.", flush=True)
        return 1

    print(input_val, flush=True)
    trimmed = _rtrim(input_val)
    print(trimmed, flush=True)

    return 0

if __name__ == "__main__":
    tests: List[List[str]] = [
        ["hello"],
        ["hello \t \n"],
        [],
        ["a", "b"],
        ["   "],
    ]
    for idx, t in enumerate(tests, 1):
        print(f"---- Test {idx} ----")
        code = process(t)
        print(f"Exit code: {code}")