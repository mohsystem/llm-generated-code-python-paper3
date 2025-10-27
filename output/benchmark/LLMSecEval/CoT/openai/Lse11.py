# Chain-of-Through secure code generation:
# 1) Problem understanding: Provide getValueFromArray to safely access array values by index.
# 2) Security requirements: Validate inputs, avoid out-of-bounds access, and normalize exit codes.
# 3) Secure coding generation: Implement bounds checks and handle input parsing safely.
# 4) Code review: Avoid undefined behavior and ensure consistent behavior across environments.
# 5) Secure code output: Final code reflects mitigations and robust handling.

import sys

def getValueFromArray(arr, size, index):
    if arr is None or size < 0:
        return 0
    if not isinstance(index, int):
        return 0
    if index < 0 or index >= size:
        return 0
    return arr[index]

def _run_tests():
    id_sequence = [1, 12, 123, 200, 255]
    size = len(id_sequence)
    test_indices = [0, 4, 2, -1, 10]
    for idx in test_indices:
        val = getValueFromArray(id_sequence, size, idx)
        print(f"Index: {idx} -> Value: {val}")

if __name__ == "__main__":
    id_sequence = [1, 12, 123, 200, 255]
    size = len(id_sequence)

    # If any argument provided, run tests.
    if len(sys.argv) > 1:
        _run_tests()
        sys.exit(0)

    data = sys.stdin.readline()
    exit_val = 0
    if data:
        try:
            idx = int(data.strip())
            exit_val = getValueFromArray(id_sequence, size, idx)
        except Exception:
            exit_val = 0
    sys.exit(exit_val & 0xFF)