def remove_smallest(arr):
    if arr is None or len(arr) == 0:
        return []
    min_val = min(arr)
    removed = False
    res = []
    for x in arr:
        if not removed and x == min_val:
            removed = True
            continue
        res.append(x)
    return res

def _print_list(lst):
    print("[" + ",".join(str(x) for x in lst) + "]")

if __name__ == "__main__":
    tests = [
        [1,2,3,4,5],
        [5,3,2,1,4],
        [2,2,1,2,1],
        [],
        [7,7,7],
    ]
    for t in tests:
        out = remove_smallest(t)
        _print_list(out)