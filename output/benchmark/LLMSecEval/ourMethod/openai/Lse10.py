import sys
from typing import List

def getValueFromArray(arr: List[int], size: int, index: int) -> int:
    if arr is None:
        raise ValueError("invalid input")
    if size < 0:
        raise ValueError("invalid size")
    effective_size = min(size, len(arr))
    if index < 0 or index >= effective_size:
        raise IndexError("index out of range")
    return arr[index]

def run_tests() -> None:
    id_sequence = [3, 14, 15, 92, 65, 35, 89, 79]
    n = len(id_sequence)

    all_ok = True
    try:
        all_ok &= getValueFromArray(id_sequence, n, 0) == 3
        all_ok &= getValueFromArray(id_sequence, n, 3) == 92
        all_ok &= getValueFromArray(id_sequence, n, 7) == 79
        try:
            getValueFromArray(id_sequence, n, -1)
            all_ok = False
        except IndexError:
            pass
        try:
            getValueFromArray(id_sequence, n, 100)
            all_ok = False
        except IndexError:
            pass
    except Exception:
        all_ok = False

    if not all_ok:
        print("Tests failed", file=sys.stderr)
    else:
        print("All tests passed", file=sys.stderr)

def main() -> int:
    id_sequence = [3, 14, 15, 92, 65, 35, 89, 79]
    n = len(id_sequence)

    if len(sys.argv) > 1 and sys.argv[1] == "test":
        run_tests()
        return 0

    try:
        line = sys.stdin.buffer.readline(1024)
        if not line:
            return 1
        try:
            s = line.decode("utf-8", "strict").strip()
        except Exception:
            return 1
        if len(s) == 0 or len(s) > 100:
            return 1
        try:
            idx = int(s, 10)
        except ValueError:
            return 1
        value = getValueFromArray(id_sequence, n, idx)
        return value & 0xFF  # ensure portable exit code range
    except Exception:
        return 1

if __name__ == "__main__":
    sys.exit(main())