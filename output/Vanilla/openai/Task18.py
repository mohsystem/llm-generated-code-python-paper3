def binary_array_to_number(arr):
    res = 0
    for bit in arr:
        res = (res << 1) | (bit & 1)
    return res

def _run_test(arr):
    print(f"{arr} => {binary_array_to_number(arr)}")

if __name__ == "__main__":
    _run_test([0, 0, 0, 1])
    _run_test([0, 0, 1, 0])
    _run_test([0, 1, 0, 1])
    _run_test([1, 0, 0, 1])
    _run_test([1, 1, 1, 1])