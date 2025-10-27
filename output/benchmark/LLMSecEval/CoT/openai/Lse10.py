"""
Chain-of-Through process:
1) Problem understanding: Provide getValueFromArray(arr, size, idx) and main that reads an int, calls it with id_sequence, and exits with the returned value.
2) Security requirements: Validate inputs, prevent out-of-bounds, sanitize exit code to 0..255, handle malformed input safely.
3) Secure coding: Explicit checks; exceptions on invalid input; no undefined behavior.
4) Code review: Ensured bounds checks and sanitized exit.
5) Secure output: If no input, run 5 tests; otherwise exit with sanitized value.
"""
import sys

def getValueFromArray(arr, size, index):
    if arr is None:
        raise ValueError("Array is None")
    if size < 0 or size > len(arr):
        raise ValueError("Invalid size")
    if index < 0 or index >= size:
        raise IndexError("Index out of range")
    return arr[index]

def _to_exit_code(value):
    return int(value) & 0xFF  # 0..255

def _run_tests():
    id_sequence = [10, 20, 30, 40, 50, 60, 70]
    size = len(id_sequence)
    tests = [0, 3, 4, 6, 10]  # last is out-of-bounds
    print("Test mode: demonstrating 5 test cases")
    for idx in tests:
        try:
            v = getValueFromArray(id_sequence, size, idx)
            print(f"Index {idx} -> {v}")
        except Exception as e:
            print(f"Index {idx} -> error: {e}")

def main():
    id_sequence = [10, 20, 30, 40, 50, 60, 70]
    size = len(id_sequence)

    data = sys.stdin.read().strip()
    if data:
        try:
            idx = int(data.split()[0])
        except Exception:
            print("Error: input is not a valid integer", file=sys.stderr)
            sys.exit(1)
        try:
            value = getValueFromArray(id_sequence, size, idx)
            sys.exit(_to_exit_code(value))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        _run_tests()
        sys.exit(0)

if __name__ == "__main__":
    main()