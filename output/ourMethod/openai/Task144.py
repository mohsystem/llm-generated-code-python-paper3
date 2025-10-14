from typing import List

def merge_sorted(a: List[int], b: List[int]) -> List[int]:
    if not isinstance(a, list) or not isinstance(b, list):
        raise TypeError("Inputs must be lists of integers.")
    if any(not isinstance(x, int) for x in a) or any(not isinstance(x, int) for x in b):
        raise TypeError("All elements must be integers.")
    if not _is_non_decreasing(a) or not _is_non_decreasing(b):
        raise ValueError("Input lists must be sorted in non-decreasing order.")

    i, j = 0, 0
    result: List[int] = []
    total_len = len(a) + len(b)
    result.reserve if hasattr(result, "reserve") else None  # No-op, Python list auto-grows

    while i < len(a) and j < len(b):
        if a[i] <= b[j]:
            result.append(a[i])
            i += 1
        else:
            result.append(b[j])
            j += 1
    if i < len(a):
        result.extend(a[i:])
    if j < len(b):
        result.extend(b[j:])
    if len(result) != total_len:
        raise RuntimeError("Unexpected merge size mismatch.")
    return result

def _is_non_decreasing(seq: List[int]) -> bool:
    for i in range(1, len(seq)):
        if seq[i - 1] > seq[i]:
            return False
    return True

def _print_list(lst: List[int]) -> None:
    print(lst)

if __name__ == "__main__":
    # Test case 1: both empty
    print(merge_sorted([], []))
    # Test case 2: one empty (b empty)
    print(merge_sorted([1, 3, 5], []))
    # Test case 3: one empty (a empty)
    print(merge_sorted([], [2, 4, 6]))
    # Test case 4: duplicates
    print(merge_sorted([1, 2, 2, 3], [2, 2, 4]))
    # Test case 5: negatives and positives
    print(merge_sorted([-5, -2, 0], [-3, -1, 2]))