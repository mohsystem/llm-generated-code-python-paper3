from typing import List

def create_phone_number(numbers: List[int]) -> str:
    if numbers is None:
        raise ValueError("Input list must not be None")
    if len(numbers) != 10:
        raise ValueError("Input list must have exactly 10 digits")
    for idx, d in enumerate(numbers):
        if not isinstance(d, int):
            raise ValueError(f"Each element must be an int at index {idx}")
        if d < 0 or d > 9:
            raise ValueError(f"Each element must be in range 0..9 at index {idx}")
    area = "".join(str(d) for d in numbers[0:3])
    prefix = "".join(str(d) for d in numbers[3:6])
    line = "".join(str(d) for d in numbers[6:10])
    return f"({area}) {prefix}-{line}"

def _run_test(arr):
    try:
        print(f"{arr} -> {create_phone_number(arr)}")
    except Exception as e:
        print(f"{arr} -> ERROR: {e}")

if __name__ == "__main__":
    _run_test([1,2,3,4,5,6,7,8,9,0])     # valid
    _run_test([0,0,0,0,0,0,0,0,0,0])     # valid
    _run_test([9,7,6,5,4,3,2,1,0,9])     # valid
    _run_test([1,2,3,4,5,6,7,8,9])       # invalid length
    _run_test([1,2,3,4,5,6,7,8,9,10])    # invalid digit