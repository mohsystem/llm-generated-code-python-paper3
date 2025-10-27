def copy_and_free(src):
    if src is None or len(src) != 10:
        raise ValueError("src must be length 10")
    first = [0]*10
    for i in range(10):
        first[i] = src[i]
    second = [0]*10
    for i in range(10):
        second[i] = first[i]
    result = second.copy()
    del first
    del second
    return result

if __name__ == "__main__":
    tests = [
        [0,1,2,3,4,5,6,7,8,9],
        [10,11,12,13,14,15,16,17,18,19],
        [5,5,5,5,5,5,5,5,5,5],
        [-5,-4,-3,-2,-1,0,1,2,3,4],
        [42,0,-7,13,13,-1,2,2,999,-999]
    ]
    for i, t in enumerate(tests, 1):
        out = copy_and_free(t)
        print(f"Test {i}: {out}")