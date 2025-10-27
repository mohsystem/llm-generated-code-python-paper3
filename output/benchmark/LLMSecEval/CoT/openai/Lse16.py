# Chain-of-Through process in code generation:
# 1) Problem understanding: Return value at a given index from a predefined array.
# 2) Security requirements: Prevent out-of-bounds access and invalid indices.
# 3) Secure coding generation: Validate inputs; raise exceptions on invalid indices.
# 4) Code review: Ensure no unsafe operations or unchecked accesses.
# 5) Secure code output: Final function with checks and predictable behavior.

DATA = (10, 20, 30, 40, 50, 60, 70, 80, 90, 100)

def value_at_index(index: int) -> int:
    if not isinstance(index, int):
        raise TypeError("Index must be an integer")
    if index < 0 or index >= len(DATA):
        raise IndexError(f"Index out of bounds: {index}")
    return DATA[index]

if __name__ == "__main__":
    tests = [0, 5, 9, 3, 7]
    for idx in tests:
        try:
            val = value_at_index(idx)
            print(f"Index {idx} -> {val}")
        except Exception as e:
            print(f"Error for index {idx}: {e}")