# Chain-of-Through process:
# 1. Problem understanding:
#    - Sort a list of integers ascending, return a new list without mutating input.
# 2. Security requirements:
#    - Handle None safely, avoid side effects, use built-in sorted for safety and performance.
# 3. Secure coding generation:
#    - Validate input type minimally, copy via sorted to avoid mutation.
# 4. Code review:
#    - No external I/O or eval, pure function, handles edge cases (None, empty).
# 5. Secure code output:
#    - Implemented as below.

from typing import List, Optional

def sort_array(arr: Optional[List[int]]) -> List[int]:
    if arr is None:
        return []
    # Ensure all elements are integers; if not, raise TypeError to maintain correctness
    if not all(isinstance(x, int) for x in arr):
        raise TypeError("All elements must be integers.")
    return sorted(arr)


if __name__ == "__main__":
    # 5 test cases
    tests = [
        [],                                  # empty
        [1, 2, 3, 4, 5],                      # already sorted
        [5, 4, 3, 2, 1],                      # reverse
        [3, 1, 2, 1, 3, 2, 2, 1],             # duplicates
        [-10, 0, 500000, -200, 42, 42],       # negatives and large values
    ]
    for t in tests:
        print(sort_array(t))