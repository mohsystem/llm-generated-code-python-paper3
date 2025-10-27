from dataclasses import dataclass
from typing import Optional

MAX_ALLOC_SIZE = 100 * 1024 * 1024  # 100 MiB cap

def allocate_memory(size: int) -> Optional[bytearray]:
    if not isinstance(size, int) or size < 0 or size > MAX_ALLOC_SIZE:
        return None
    try:
        return bytearray(size)  # zero-initialized
    except MemoryError:
        return None

@dataclass
class Person:
    status: int
    name: str

def create_default_person() -> Person:
    return Person(status=0, name="John")

if __name__ == "__main__":
    a1 = allocate_memory(16)
    print(f"Test1 allocate 16 -> {len(a1) if a1 is not None else 'null'}")

    a2 = allocate_memory(0)
    print(f"Test2 allocate 0 -> {len(a2) if a2 is not None else 'null'}")

    a3 = allocate_memory(1_048_576)
    print(f"Test3 allocate 1_048_576 -> {len(a3) if a3 is not None else 'null'}")

    a4 = allocate_memory(-5)
    print(f"Test4 allocate -5 -> {len(a4) if a4 is not None else 'null'}")

    p = create_default_person()
    print(f"Test5 create person -> {{'name': '{p.name}', 'status': {p.status}}}")