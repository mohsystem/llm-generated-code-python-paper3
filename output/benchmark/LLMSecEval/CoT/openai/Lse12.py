import sys

def getValueFromArray(arr, size, index):
    if arr is None or size <= 0:
        return 0
    size = min(size, len(arr))
    if isinstance(index, int) and 0 <= index < size:
        return arr[index]
    return 0

def run_tests():
    arr = [10, 20, 30, 40, 50]
    size = len(arr)
    tests = [0, 2, 4, -1, 10]
    for i, idx in enumerate(tests, 1):
        res = getValueFromArray(arr, size, idx)
        print(f"Test {i}: index={idx} value={res}")

def main():
    run_tests()

    arr = [10, 20, 30, 40, 50]
    size = len(arr)
    index = 0
    try:
        line = sys.stdin.readline()
        if line:
            line = line.strip()
            if line:
                index = int(line)
    except Exception:
        index = 0
    value = getValueFromArray(arr, size, index)
    sys.exit(value)

if __name__ == "__main__":
    main()