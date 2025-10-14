from typing import List, Optional

def remove_smallest(arr: Optional[List[int]]) -> List[int]:
    if not arr:
        return []
    min_idx = 0
    min_val = arr[0]
    for i in range(1, len(arr)):
        if arr[i] < min_val:
            min_val = arr[i]
            min_idx = i
    return [arr[i] for i in range(len(arr)) if i != min_idx]

def _print_list(lst: List[int]) -> None:
    print(str(lst))

if __name__ == "__main__":
    tests = [
        [1, 2, 3, 4, 5],
        [5, 3, 2, 1, 4],
        [2, 2, 1, 2, 1],
        [],
        [7],
    ]
    for t in tests:
        res = remove_smallest(t)
        _print_list(res)