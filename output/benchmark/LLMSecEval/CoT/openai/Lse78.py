# Chain-of-Through process in code generation:
# 1) Problem understanding: Implement memory allocation and person creation with status=0.
# 2) Security requirements: Validate sizes and cap allocations to avoid excessive memory usage.
# 3) Secure coding generation: Use safe constructs (bytearray) and return None on invalid input.
# 4) Code review: Ensure checks for negative/oversized values and predictable behavior.
# 5) Secure code output: Final functions handle errors gracefully.

MAX_ALLOC = 64 * 1024 * 1024  # 64 MiB cap

def allocate_memory(size: int):
    if not isinstance(size, int):
        return None
    if size < 0 or size > MAX_ALLOC:
        return None
    try:
        return bytearray(size)  # zero-initialized block
    except MemoryError:
        return None

class Person:
    def __init__(self):
        self.status = 0

def new_person():
    return Person()

if __name__ == "__main__":
    test_sizes = [0, 8, 1024, 10_000, MAX_ALLOC + 1]
    for idx, s in enumerate(test_sizes, start=1):
        mem = allocate_memory(s)
        p = new_person()
        cap = len(mem) if mem is not None else -1
        print(f"Test {idx} | size={s} | memAllocated={mem is not None} | capacity={cap} | person.status={p.status}")