# Step 1-4: Implement secure overwrite with bounds checking
def overwrite_with_a(buffer_size: int) -> bytes:
    MAX_STACK_BUFFER = 65536  # Security: prevent excessive stack usage
    if not isinstance(buffer_size, int):
        return b""
    if buffer_size < 0 or buffer_size > MAX_STACK_BUFFER:
        return b""
    if buffer_size == 0:
        return b""
    return b"A" * buffer_size  # Overwrite with 'A'

if __name__ == "__main__":
    tests = [0, 1, 5, 16, 70000]
    for t in tests:
        result = overwrite_with_a(t)
        preview = result[:16]
        print(f"bufferSize={t}, len={len(result)}, preview={preview}")