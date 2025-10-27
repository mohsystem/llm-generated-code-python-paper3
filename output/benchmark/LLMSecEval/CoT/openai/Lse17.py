# Chain-of-Through process:
# 1) Problem understanding: Provide a function returning the value at a specified index in a list safely.
# 2) Security requirements: Validate inputs to avoid IndexError/TypeError and do not trust user input.
# 3) Secure coding generation: Check list type, length, and index bounds before access.
# 4) Code review: Ensured no direct unsafe indexing without checks.
# 5) Secure code output: Returns (success, value) tuple; value is None if invalid.

from typing import List, Tuple, Optional

def get_value_at_index(arr: Optional[List[int]], index: int) -> Tuple[bool, Optional[int]]:
    if arr is None or not isinstance(arr, list):
        return (False, None)
    if not isinstance(index, int):
        return (False, None)
    if index < 0 or index >= len(arr):
        return (False, None)
    return (True, arr[index])

if __name__ == "__main__":
    data = [10, 20, 30, 40, 50]
    test_indices = [0, 2, 4, -1, 10]

    for idx in test_indices:
        ok, val = get_value_at_index(data, idx)
        if ok:
            print(f"Index {idx} -> {val}")
        else:
            print(f"Index {idx} -> invalid index")