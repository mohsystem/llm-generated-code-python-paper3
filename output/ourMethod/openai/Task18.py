from typing import List

def binary_array_to_int(bits: List[int]) -> int:
    if bits is None:
        raise ValueError("Input list must not be None.")
    result = 0
    for idx, bit in enumerate(bits):
        if not isinstance(bit, int) or bit not in (0, 1):
            raise ValueError(f"Invalid bit at index {idx}: {bit}. Only integers 0 or 1 are allowed.")
        result = (result << 1) | bit
    return result

def _fmt(bits: List[int]) -> str:
    return "[" + ", ".join(str(b) for b in bits) + "]"

if __name__ == "__main__":
    tests: List[List[int]] = [
        [0, 0, 0, 1],
        [0, 0, 1, 0],
        [0, 1, 0, 1],
        [1, 0, 0, 1],
        [1, 1, 1, 1],
    ]
    for t in tests:
        try:
            res = binary_array_to_int(t)
            print(f"Testing: {_fmt(t)} ==> {res}")
        except ValueError as e:
            print(f"Error for input {_fmt(t)}: {e}")