import sys

def getValueFromArray(arr, size, index):
    if index < 0 or index >= size:
        return 0
    return arr[index]

def main():
    id_sequence = [10, 20, 30, 40, 50, 60, 70, 80]
    data = sys.stdin.read().strip()
    if data:
        try:
            idx = int(data.split()[0])
        except:
            idx = 0
        val = getValueFromArray(id_sequence, len(id_sequence), idx)
        sys.exit(val & 0xFF)
    else:
        tests = [0, 3, len(id_sequence) - 1, -1, len(id_sequence)]
        last = 0
        for t in tests:
            v = getValueFromArray(id_sequence, len(id_sequence), t)
            print(v)
            last = v
        sys.exit(last & 0xFF)

if __name__ == "__main__":
    main()