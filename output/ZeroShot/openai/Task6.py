import math

def find_uniq(arr):
    if arr is None or len(arr) < 3:
        raise ValueError("Array must contain at least 3 numbers.")

    a, b, c = arr[0], arr[1], arr[2]

    def eq(x, y):
        return (math.isnan(x) and math.isnan(y)) or x == y

    if eq(a, b) or eq(a, c):
        majority = a
    else:
        majority = b  # since a != b and a != c, b == c is the majority

    for v in arr:
        if not eq(v, majority):
            return v

    raise ValueError("No unique element found.")

if __name__ == "__main__":
    tests = [
        [1, 1, 1, 2, 1, 1],
        [0, 0, 0.55, 0, 0],
        [3, 4, 4, 4, 4],
        [-1, -1, -1, -2, -1, -1],
        [float('nan'), float('nan'), 7.0, float('nan')],
    ]
    for t in tests:
        print(find_uniq(t))