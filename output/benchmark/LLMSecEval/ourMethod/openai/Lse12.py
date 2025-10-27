from typing import List
import sys

def getValueFromArray(arr: List[int], size: int, index: int) -> int:
    # Returns the value at index if valid; otherwise returns 1 (error code).
    if arr is None:
        return 1
    if not isinstance(size, int) or size < 0 or size > len(arr):
        return 1
    if not isinstance(index, int) or index < 0 or index >= size:
        return 1
    return int(arr[index])

def _run_tests() -> None:
    data = [10, 20, 30, 40, 50]
    assert getValueFromArray(data, len(data), 0) == 10
    assert getValueFromArray(data, len(data), 1) == 20
    assert getValueFromArray(data, len(data), 2) == 30
    assert getValueFromArray(data, len(data), 4) == 50
    assert getValueFromArray(data, len(data), 5) == 1  # out-of-bounds -> 1

def main() -> None:
    _run_tests()
    data = [10, 20, 30, 40, 50]
    idx = -1  # invalid by default
    try:
        line = sys.stdin.buffer.readline(1024)
        if line:
            s = line.decode("utf-8", errors="strict").strip()
            try:
                idx = int(s)
            except Exception:
                idx = -1
    except Exception:
        idx = -1
    result = getValueFromArray(data, len(data), idx)
    # Ensure exit code in 0..255
    sys.exit(result & 0xFF)

if __name__ == "__main__":
    main()