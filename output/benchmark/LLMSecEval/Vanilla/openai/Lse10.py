import sys

def getValueFromArray(arr, size, index):
    if 0 <= index < size:
        return arr[index]
    return 0

if __name__ == "__main__":
    id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    size = len(id_sequence)

    # 5 test cases
    test_indices = [0, 4, 9, -1, 100]
    for i, idx in enumerate(test_indices, start=1):
        val = getValueFromArray(id_sequence, size, idx)
        print(f"test{i}: idx={idx}, val={val}")

    idx = 0
    try:
        line = sys.stdin.readline()
        if line:
            idx = int(line.strip())
    except:
        idx = 0

    res = getValueFromArray(id_sequence, size, idx)
    sys.exit(res)