# Step 1-5: Secure, bounds-checked retrieval from a fixed array.
DATA = (10, 20, 30, 40, 50, 60, 70, 80, 90, 100)

def get_value_at_index(index: int) -> int:
    if not isinstance(index, int):
        return -1
    if index < 0 or index >= len(DATA):
        return -1
    return DATA[index]

if __name__ == "__main__":
    test_cases = [5, 0, 9, -1, 10]
    for idx in test_cases:
        print(f"Index {idx} -> {get_value_at_index(idx)}")