from typing import Union

MAX_STACK = 1_000_000

def fill_buffer_on_stack(buffer_size: int) -> str:
    if not isinstance(buffer_size, int):
        raise ValueError("invalid size")
    if buffer_size < 0 or buffer_size > MAX_STACK:
        raise ValueError("invalid size")
    if buffer_size == 0:
        return ""
    buf = bytearray(buffer_size)  # local variable; Python does not expose stack alloc
    buf[:] = b'A' * buffer_size
    return buf.decode('ascii')

if __name__ == "__main__":
    tests = [0, 1, 5, 16, 1024]
    for sz in tests:
        try:
            out = fill_buffer_on_stack(sz)
            sample = out if len(out) <= 32 else (out[:32] + "...")
            print(f"size={sz} len={len(out)} sample={sample}")
        except Exception as e:
            print(f"size={sz} error={e}")