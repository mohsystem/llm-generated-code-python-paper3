def find_even_index(arr):
    if arr is None or len(arr) == 0:
        return -1
    total = sum(arr)
    left = 0
    for i, v in enumerate(arr):
        right = total - left - v
        if left == right:
            return i
        left += v
    return -1

if __name__ == "__main__":
    tests = [
        [1,2,3,4,3,2,1],          # expect 3
        [1,100,50,-51,1,1],       # expect 1
        [20,10,-80,10,10,15,35],  # expect 0
        [1,2,3,4,5],              # expect -1
        [0,0,0]                   # expect 0
    ]
    for i, arr in enumerate(tests, 1):
        print(f"Test {i} arr={arr} -> {find_even_index(arr)}")