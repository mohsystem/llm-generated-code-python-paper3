from typing import Iterable, Optional

def allocate_copy_free(data: Optional[Iterable[int]]) -> bytes:
    """
    Allocates two chunks of size 10, copies first to second, frees both (via zeroing and del),
    returns a detached copy of the second chunk.
    """
    SIZE = 10

    # Initialize chunk1 with zeros
    chunk1 = bytearray(SIZE)

    if data is not None:
        # Normalize input to a bytes-like sequence of ints 0..255
        if isinstance(data, (bytes, bytearray)):
            src = bytes(data)
        else:
            src = bytes([(int(x) & 0xFF) for x in data])
        copy_len = min(len(src), SIZE)
        if copy_len > 0:
            chunk1[:copy_len] = src[:copy_len]

    # Allocate chunk2 and copy
    chunk2 = bytearray(SIZE)
    chunk2[:] = chunk1  # bounded copy of size 10

    # Detach a result before freeing chunks
    result = bytes(chunk2)

    # Zeroize then delete references (simulate freeing)
    for i in range(SIZE):
        chunk1[i] = 0
        chunk2[i] = 0
    del chunk1
    del chunk2

    return result


if __name__ == "__main__":
    # 5 test cases
    tests = [
        [1, 2, 3],
        None,
        bytes(range(10)),
        bytes(range(11)),  # longer than 10; only first 10 used
        [],                # empty
    ]
    for idx, t in enumerate(tests, 1):
        out = allocate_copy_free(t)
        print(f"Test {idx}:", list(out))