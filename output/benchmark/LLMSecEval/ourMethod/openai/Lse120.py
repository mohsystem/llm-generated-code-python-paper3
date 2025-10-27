from typing import Optional

MAX_SIZE = 1 << 20  # 1 MiB


def copy_chunk(data: bytes) -> Optional[bytes]:
    """
    Allocates two chunks, copies the first into the second, returns the second.
    Returns None if input is invalid or exceeds limits.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    size = len(data)
    if size > MAX_SIZE:
        return None

    # Allocate first chunk and copy data into it
    first = bytearray(size)
    if size:
        first[:size] = data

    # Allocate second chunk and copy first into it
    second = bytearray(size)
    if size:
        second[:size] = first

    return bytes(second)


def run_test(data: bytes, label: str) -> None:
    print(f"Test: {label}")
    out = copy_chunk(data)
    if out is None:
        print("[ERROR] Copy failed or input too large.")
    else:
        # Decode for display; replace errors to avoid exceptions on arbitrary bytes
        print(out.decode("utf-8", errors="replace"))
    print("----")


def main() -> None:
    # Test 1: Empty
    run_test(b"", "Empty")

    # Test 2: Simple text
    run_test("Hello, world!".encode("utf-8"), "Simple text")

    # Test 3: Unicode text
    run_test("Unicode test: 你好, мир, مرحبا".encode("utf-8"), "Unicode text")

    # Test 4: Large but within limit
    run_test(b"A" * 100_000, "Large within limit")

    # Test 5: Oversized (exceeds MAX_SIZE)
    run_test(b"B" * (MAX_SIZE + 1), "Oversized")


if __name__ == "__main__":
    main()