# Task26 - Python implementation
# 1) Understand: Find the integer that appears an odd number of times (exactly one exists).
# 2-5) Secure coding: handle None/empty; XOR reduction.

def find_odd_occurrence(arr):
    if arr is None or len(arr) == 0:
        return 0  # Safe default
    x = 0
    for v in arr:
        x ^= int(v)
    return x

if __name__ == "__main__":
    # 5 test cases
    print(find_odd_occurrence([7]))  # 7
    print(find_odd_occurrence([0]))  # 0
    print(find_odd_occurrence([1, 1, 2]))  # 2
    print(find_odd_occurrence([0, 1, 0, 1, 0]))  # 0
    print(find_odd_occurrence([1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1]))  # 4