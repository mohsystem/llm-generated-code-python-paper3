from typing import Union

MAX_SIZE = 1 << 20  # 1 MiB cap

def demo_copy(data: Union[str, bytes]) -> bytes:
    # Normalize input to bytes (UTF-8)
    if isinstance(data, str):
        src = data.encode('utf-8')
    elif isinstance(data, (bytes, bytearray)):
        src = bytes(data)
    else:
        print("Invalid input")
        return b""

    if len(src) > MAX_SIZE:
        print("Input too large")
        return b""

    # Allocate two chunks
    chunk1 = bytearray(len(src))
    chunk2 = bytearray(len(src))

    # Copy input -> chunk1
    if len(chunk1) != len(src):
        print("Allocation error")
        return b""
    chunk1[:] = src

    # Copy chunk1 -> chunk2
    if len(chunk2) < len(chunk1):
        print("Allocation error")
        return b""
    chunk2[:] = chunk1

    # Print second chunk
    print(chunk2.decode('utf-8', errors='replace'))

    # "Free" first chunk
    for i in range(len(chunk1)):
        chunk1[i] = 0
    del chunk1

    # Print second chunk again (should remain unchanged)
    print(chunk2.decode('utf-8', errors='replace'))

    # Capture return before freeing second
    ret = bytes(chunk2)

    # "Free" second chunk
    for i in range(len(chunk2)):
        chunk2[i] = 0
    del chunk2

    return ret


if __name__ == "__main__":
    tests = [
        "Hello, world!",
        "",
        "A longer string with multiple words.",
        "Unicode: 😊🚀✨",
        "Line1\nLine2\tTabbed",
    ]
    for t in tests:
        result = demo_copy(t)
        print("Returned:", result.decode('utf-8', errors='replace'))
        print("---")