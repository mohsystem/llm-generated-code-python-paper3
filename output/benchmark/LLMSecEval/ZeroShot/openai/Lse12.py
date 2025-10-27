import sys

def getValueFromArray(arr, size, index):
    if arr is None:
        raise ValueError("Array is None")
    if size < 0 or size > len(arr):
        raise ValueError("Invalid size")
    if index < 0 or index >= size:
        raise IndexError("Index out of bounds")
    return arr[index]

def main():
    example = [10, 20, 30, 40, 50]
    size = len(example)

    data = sys.stdin.read()
    if data is not None:
        data = data.strip()
    if data:
        try:
            idx = int(data)
        except Exception:
            sys.exit(1)
        if idx < 0 or idx >= size:
            sys.exit(1)
        try:
            value = getValueFromArray(example, size, idx)
        except Exception:
            sys.exit(1)
        sys.exit(value & 0xFF)
    else:
        # No input provided: run 5 test cases
        for i in range(size):
            try:
                v = getValueFromArray(example, size, i)
                print(f"Test {i+1}: {v}")
            except Exception:
                print(f"Test {i+1}: error")
        sys.exit(0)

if __name__ == "__main__":
    main()