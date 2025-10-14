# Dynamically allocates a buffer, fills it, and returns the value at the given index.
# Returns -1 for invalid size or out-of-bounds index.
def read_from_buffer(size: int, index: int, fill_base: int = 100) -> int:
    if size <= 0:
        return -1
    buffer = [fill_base + i for i in range(size)]  # dynamic allocation
    if index < 0 or index >= size:
        return -1
    return buffer[index]

if __name__ == "__main__":
    size = 5
    fill_base = 100
    test_indices = [0, 4, 5, -1, 2]
    for idx in test_indices:
        result = read_from_buffer(size, idx, fill_base)
        print(f"Index {idx} -> {result}")