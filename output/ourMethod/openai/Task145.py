from typing import List, Tuple, Sequence

MIN_LL = -(1 << 63)
MAX_LL = (1 << 63) - 1

def _will_add_overflow(a: int, b: int) -> bool:
    if b > 0 and a > MAX_LL - b:
        return True
    if b < 0 and a < MIN_LL - b:
        return True
    return False

def max_subarray_sum(arr: Sequence[int]) -> Tuple[bool, int, str]:
    if arr is None or len(arr) == 0:
        return (False, 0, "invalid input: null or empty array")
    # Validate elements
    for x in arr:
        if not isinstance(x, int):
            return (False, 0, "invalid input: non-integer element detected")
        if x < MIN_LL or x > MAX_LL:
            return (False, 0, "invalid input: element out of 64-bit range")

    current = arr[0]
    best = arr[0]

    for x in arr[1:]:
        if _will_add_overflow(current, x):
            return (False, 0, "sum overflow detected")
        s = current + x
        current = x if x > s else s
        best = current if current > best else best

    return (True, best, "")

def _run_test(test_id: int, input_arr: List[int], expected: int = None) -> None:
    ok, value, err = max_subarray_sum(input_arr)
    print(f"Test {test_id}: input={input_arr}")
    if ok:
        if expected is not None:
            print(f"  ok=True, max_sum={value}, expected={expected}")
        else:
            print(f"  ok=True, max_sum={value}")
    else:
        print(f"  ok=False, error={err}")

if __name__ == "__main__":
    t1 = [-2, 1, -3, 4, -1, 2, 1, -5, 4]  # 6
    t2 = [1, 2, 3, 4]  # 10
    t3 = [-1, -2, -3]  # -1
    t4 = [5, -9, 6, -2, 3]  # 7
    t5: List[int] = []  # error: empty

    _run_test(1, t1, 6)
    _run_test(2, t2, 10)
    _run_test(3, t3, -1)
    _run_test(4, t4, 7)
    _run_test(5, t5)