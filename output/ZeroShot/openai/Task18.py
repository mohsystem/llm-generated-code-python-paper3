from typing import Iterable

def binary_array_to_int(arr: Iterable[int]) -> int:
    if arr is None:
        raise ValueError("Input cannot be None")
    acc = 0
    for idx, bit in enumerate(arr):
        if not isinstance(bit, int) or bit not in (0, 1):
            raise ValueError(f"Array must contain only integers 0 or 1 at index {idx}")
        acc = (acc << 1) | bit
    return acc

if __name__ == "__main__":
    tests = [
        [0, 0, 0, 1],  # 1
        [0, 0, 1, 0],  # 2
        [0, 1, 0, 1],  # 5
        [1, 0, 0, 1],  # 9
        [1, 1, 1, 1],  # 15
    ]
    for t in tests:
        try:
            print(f"Testing: {t} ==> {binary_array_to_int(t)}")
        except Exception as e:
            print(f"Error for {t}: {e}")