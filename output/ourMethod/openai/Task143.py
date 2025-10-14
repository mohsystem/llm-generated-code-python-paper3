from typing import List

MAX_LEN: int = 1_000_000
INT_MIN: int = -2_147_483_648
INT_MAX: int = 2_147_483_647

def sort_ascending(arr: List[int]) -> List[int]:
    if not isinstance(arr, list):
        raise ValueError("Input must be a list of integers.")
    if len(arr) > MAX_LEN:
        raise ValueError("Input list too large.")
    for idx, v in enumerate(arr):
        if not isinstance(v, int):
            raise ValueError(f"Element at index {idx} is not an int.")
        if v < INT_MIN or v > INT_MAX:
            raise ValueError(f"Element at index {idx} out of 32-bit int range.")
    return list(sorted(arr))

def _run_test(test_number: int, input_list: List[int]) -> None:
    try:
        result = sort_ascending(input_list)
        print(f"Test {test_number} input:  {input_list}")
        print(f"Test {test_number} output: {result}")
    except ValueError as e:
        print(f"Test {test_number} error: {e}")
    print("----")

if __name__ == "__main__":
    t1 = [3, 1, 2]
    t2 = [-5, -10, 0, 5]
    t3: List[int] = []
    t4 = [1, 1, 1, 1]
    t5 = [2_147_483_647, -2_147_483_648, 0, -1, 1]

    _run_test(1, t1)
    _run_test(2, t2)
    _run_test(3, t3)
    _run_test(4, t4)
    _run_test(5, t5)