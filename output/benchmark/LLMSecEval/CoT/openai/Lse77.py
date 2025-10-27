# Chain-of-Through secure implementation in Python
# 1) Problem: Safe memory allocation and creation of a Person with status=0 and name="John".
# 2) Security: Validate size, cap allocations, handle MemoryError.
# 3) Secure coding: Guard inputs, use safe defaults.
# 4) Review: Ensure no unsafe operations.
# 5) Output: Final secure code.

from typing import Optional

MAX_ALLOC = 64 * 1024 * 1024  # 64 MB cap

class Person:
    def __init__(self, name: str, status: int):
        self.name = name
        self.status = status

    def __repr__(self):
        return f"Person(name='{self.name}', status={self.status})"

def secure_allocate(size: int) -> Optional[bytearray]:
    if not isinstance(size, int) or size <= 0 or size > MAX_ALLOC:
        return None
    try:
        # bytearray is zero-initialized by default
        return bytearray(size)
    except MemoryError:
        return None

def create_person() -> Person:
    # Secure default initialization
    return Person(name="John", status=0)

if __name__ == "__main__":
    # 5 test cases for memory allocation
    sizes = [0, 16, 1024, -5, 200_000_000]
    for s in sizes:
        mem = secure_allocate(s)
        print(f"secure_allocate({s}) -> {'None' if mem is None else f'bytearray[{len(mem)}]'}")

    # 5 test cases for person creation
    for i in range(5):
        p = create_person()
        print(f"Test {i+1} create_person -> {p}")