# Note: Python does not support explicit stack allocation; objects are heap-allocated.
def fill_buffer(buffer_size: int):
    n = max(0, buffer_size)
    return 'A' * n

if __name__ == "__main__":
    tests = [0, 1, 5, 10, 100]
    for t in tests:
        s = fill_buffer(t)
        print(f"size={t} -> \"{s}\"")