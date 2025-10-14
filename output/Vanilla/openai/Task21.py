def remove_smallest(arr):
    if not arr:
        return []
    min_val = min(arr)
    idx = arr.index(min_val)
    return arr[:idx] + arr[idx+1:]

if __name__ == "__main__":
    tests = [
        [1,2,3,4,5],
        [5,3,2,1,4],
        [2,2,1,2,1],
        [],
        [10]
    ]
    for t in tests:
        print(remove_smallest(t))