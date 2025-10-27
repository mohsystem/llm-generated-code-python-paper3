MAX_SAFE_SIZE = 16 * 1024 * 1024  # 16 MB cap


class Person:
    def __init__(self):
        self.status = 0  # default to 0


def allocate_memory(size: int):
    if not isinstance(size, int) or size < 0 or size > MAX_SAFE_SIZE:
        return None
    try:
        return bytearray(size)  # zero-initialized
    except MemoryError:
        return None


def allocate_person():
    return Person()


if __name__ == "__main__":
    # 5 test cases
    t1 = allocate_memory(1024)
    print(f"Test1 allocate_memory(1024): {len(t1) if t1 is not None else 'None'}")

    p1 = allocate_person()
    print(f"Test2 allocate_person(): status={p1.status if p1 is not None else 'None'}")

    t3 = allocate_memory(0)
    print(f"Test3 allocate_memory(0): {len(t3) if t3 is not None else 'None'}")

    t4 = allocate_memory(-1)
    print(f"Test4 allocate_memory(-1): {len(t4) if t4 is not None else 'None'}")

    t5 = allocate_memory(MAX_SAFE_SIZE + 1)
    print(f"Test5 allocate_memory(>MAX): {len(t5) if t5 is not None else 'None'}")