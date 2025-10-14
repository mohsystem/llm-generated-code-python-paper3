from typing import List, Optional

def pos_neg_sort(arr: Optional[List[int]]) -> Optional[List[int]]:
    if arr is None:
        return None
    positives = sorted(x for x in arr if x > 0)
    res: List[int] = []
    pi = 0
    for v in arr:
        if v > 0:
            res.append(positives[pi])
            pi += 1
        else:
            res.append(v)
    return res

if __name__ == "__main__":
    tests = [
        [6, 3, -2, 5, -8, 2, -2],
        [6, 5, 4, -1, 3, 2, -1, 1],
        [-5, -5, -5, -5, 7, -5],
        [],
        [5, -1, -3, 2, 1],
    ]
    for t in tests:
        print(pos_neg_sort(t))