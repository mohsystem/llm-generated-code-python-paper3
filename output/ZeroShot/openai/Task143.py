def sort_ascending(arr):
    if arr is None:
        return []
    return sorted(list(arr))

if __name__ == "__main__":
    # Test case 1
    t1 = [5, 2, 9, 1, 5, 6]
    print(sort_ascending(t1))

    # Test case 2
    t2 = [-3, 0, -1, -7, 2]
    print(sort_ascending(t2))

    # Test case 3
    t3 = []
    print(sort_ascending(t3))

    # Test case 4
    t4 = [42]
    print(sort_ascending(t4))

    # Test case 5
    t5 = [2**31 - 1, -2**31, 0, -1, 1]
    print(sort_ascending(t5))