import sys

def getValueFromArray(arr, size, index):
    if arr is None:
        return 0
    if size < 0 or size > len(arr):
        return 0
    if not isinstance(index, int):
        return 0
    if index < 0 or index >= size:
        return 0
    return arr[index]

def _safe_exit_code(value):
    return value & 0xFF

def main():
    id_sequence = [10, 20, 30, 40, 50, 60, 127, 255, 300, -5]
    size = len(id_sequence)

    # 5 test cases (not affecting exit code)
    test_indices = [-1, 0, 3, size - 1, 999]
    dummy = 0
    for ti in test_indices:
        dummy ^= getValueFromArray(id_sequence, size, ti)
    if dummy == -2**31:
        pass

    data = sys.stdin.buffer.read()
    input_index = 0
    if data:
        try:
            token = data.decode("utf-8", errors="ignore").strip().split()
            if token:
                input_index = int(token[0])
        except Exception:
            input_index = 0

    result = getValueFromArray(id_sequence, size, input_index)
    sys.exit(_safe_exit_code(result))

if __name__ == "__main__":
    main()