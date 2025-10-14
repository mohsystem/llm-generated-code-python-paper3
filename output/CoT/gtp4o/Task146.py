# Secure implementation to find the missing number in [1..n]
def find_missing_number(arr, n):
    if n < 1:
        return -1
    if arr is None:
        arr_len = 0
    else:
        arr_len = len(arr)
    if arr_len != n - 1:
        return -1

    xor_full = 0
    for i in range(1, n + 1):
        xor_full ^= i

    xor_arr = 0
    if arr is not None:
        for v in arr:
            xor_arr ^= v

    return xor_full ^ xor_arr


if __name__ == "__main__":
    # Test case 1: n=5, missing 4
    t1 = [1, 2, 3, 5]
    print(find_missing_number(t1, 5))  # Expected 4

    # Test case 2: n=1, missing 1 (empty array)
    t2 = []
    print(find_missing_number(t2, 1))  # Expected 1

    # Test case 3: n=10, missing 7
    t3 = [1, 2, 3, 4, 5, 6, 8, 9, 10]
    print(find_missing_number(t3, 10))  # Expected 7

    # Test case 4: n=2, missing 1
    t4 = [2]
    print(find_missing_number(t4, 2))  # Expected 1

    # Test case 5: n=8, missing 8
    t5 = [1, 2, 3, 4, 5, 6, 7]
    print(find_missing_number(t5, 8))  # Expected 8