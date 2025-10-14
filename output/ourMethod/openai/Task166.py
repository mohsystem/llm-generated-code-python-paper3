from typing import List

def pos_neg_sort(arr: List[int]) -> List[int]:
    if arr is None or len(arr) == 0:
        return []
    positives = sorted([x for x in arr if x > 0])
    result: List[int] = []
    p = 0
    for v in arr:
        if v < 0:
            result.append(v)
        else:
            result.append(positives[p])
            p += 1
    return result

def _print_test(input_arr: List[int]) -> None:
    print(f"Input:  {input_arr}")
    print(f"Output: {pos_neg_sort(input_arr)}\n")

if __name__ == "__main__":
    tests: List[List[int]] = [
        [6, 3, -2, 5, -8, 2, -2],
        [6, 5, 4, -1, 3, 2, -1, 1],
        [-5, -5, -5, -5, 7, -5],
        [],
        [-1, -3, 2, 1, 4],
    ]
    for t in tests:
        _print_test(t)