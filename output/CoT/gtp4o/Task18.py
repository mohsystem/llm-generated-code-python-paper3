# Chain-of-Through Step 1: Problem understanding
# Convert a list of 0/1 bits (MSB first) to an integer.

# Chain-of-Through Step 2: Security requirements
# - Validate input type and values are 0/1.
# - Python ints are unbounded, so overflow is not an issue here.

# Chain-of-Through Step 3: Secure coding generation
def binary_array_to_int(bits):
    if bits is None:
        raise ValueError("Input cannot be None.")
    acc = 0
    for b in bits:
        if b not in (0, 1):
            raise ValueError("List must contain only 0 or 1.")
        acc = (acc << 1) | b
    return acc

# Chain-of-Through Step 4 and 5: Review and finalize (no known vulnerabilities)
if __name__ == "__main__":
    tests = [
        [0, 0, 0, 1],  # 1
        [0, 0, 1, 0],  # 2
        [0, 1, 0, 1],  # 5
        [1, 0, 0, 1],  # 9
        [1, 1, 1, 1],  # 15
    ]
    for t in tests:
        print(f"Testing: {t} ==> {binary_array_to_int(t)}")