from typing import List

def copy_two_chunks(src: List[int]) -> List[int]:
    if src is None or len(src) != 10:
        raise ValueError("Source must be a list of length 10.")
    if any((not isinstance(x, int) or x < 0 or x > 255) for x in src):
        raise ValueError("All elements must be integers in range 0..255.")

    chunk1 = bytearray(10)
    chunk2 = bytearray(10)

    # Copy src -> chunk1
    for i in range(10):
        chunk1[i] = src[i]

    # Copy chunk1 -> chunk2
    for i in range(10):
        chunk2[i] = chunk1[i]

    # Prepare output
    out = [int(b) for b in chunk2]

    # Securely clear and delete (simulate free)
    for i in range(10):
        chunk1[i] = 0
        chunk2[i] = 0
    del chunk1
    del chunk2

    return out

if __name__ == "__main__":
    tests = [
        [0,1,2,3,4,5,6,7,8,9],
        [10,20,30,40,50,60,70,80,90,100],
        [255,254,253,252,251,250,249,248,247,246],
        [42,42,42,42,42,42,42,42,42,42],
        [9,8,7,6,5,4,3,2,1,0]
    ]
    for t in tests:
        print(copy_two_chunks(t))