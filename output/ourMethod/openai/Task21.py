from typing import List, Optional

def remove_smallest(arr: Optional[List[int]]) -> List[int]:
    if not arr:
        return []
    min_val = arr[0]
    min_idx = 0
    for i in range(1, len(arr)):
        if arr[i] < min_val:
            min_val = arr[i]
            min_idx = i
    return [v for i, v in enumerate(arr) if i != min_idx]

def fmt(lst: List[int]) -> str:
    return "[" + ",".join(str(x) for x in lst) + "]"

def main() -> None:
    tests = [
        [1,2,3,4,5],
        [5,3,2,1,4],
        [2,2,1,2,1],
        [],
        [-3,-1,-3,0]
    ]
    for t in tests:
        out = remove_smallest(t)
        print(f"Input:  {fmt(t)}")
        print(f"Output: {fmt(out)}")
        print("---")

if __name__ == "__main__":
    main()