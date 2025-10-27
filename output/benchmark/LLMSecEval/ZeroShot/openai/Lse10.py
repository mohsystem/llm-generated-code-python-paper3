import sys

def getValueFromArray(arr, size, index):
    if arr is None or size <= 0:
        return 0
    bound = min(size, len(arr))
    if 0 <= index < bound:
        return int(arr[index])
    return 0

def main():
    id_sequence = [7, 13, 42, -1, 255, 1024, -300]
    size = len(id_sequence)

    # 5 test cases
    test_indices = [0, 3, 6, -1, 100]
    for i, ti in enumerate(test_indices, 1):
        val = getValueFromArray(id_sequence, size, ti)
        print(f"Test {i} index={ti} value={val}")

    data = sys.stdin.read().split()
    idx = 0
    if data:
        try:
            v = int(data[0], 10)
        except ValueError:
            v = 0
        idx = v

    value = getValueFromArray(id_sequence, size, idx)
    exit_code = value & 0xFF
    sys.exit(exit_code)

if __name__ == "__main__":
    main()