from dataclasses import dataclass
from typing import Optional

MAX_ALLOC = 64 * 1024 * 1024  # 64MB
MAX_NAME_LEN = 128

@dataclass
class Person:
    name: str
    age: int
    status: int = 0  # status set to 0

def allocate_memory(size: int) -> bytearray:
    if not isinstance(size, int):
        raise ValueError("size type")
    if size < 0 or size > MAX_ALLOC:
        raise ValueError("invalid size")
    return bytearray(size)

def allocate_person(name: str, age: int) -> Person:
    if not isinstance(name, str):
        raise ValueError("name type")
    if not isinstance(age, int):
        raise ValueError("age type")
    if age < 0 or age > 150:
        raise ValueError("invalid age")
    nm = name.strip()
    if len(nm) > MAX_NAME_LEN:
        nm = nm[:MAX_NAME_LEN]
    return Person(name=nm, age=age, status=0)

def _preview(buf: bytearray) -> str:
    n = min(len(buf), 8)
    head = list(buf[:n])
    return f"len={len(buf)}, head={head}"

def main() -> None:
    # 5 test cases: each allocates a person and a memory block
    names = [
        "Alice",
        "Bob",
        "Charlie",
        "ThisIsAVeryLongNameThatWillBeClippedBecauseItExceedsTheMaximumAllowedLengthABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "  Eve  ",
    ]
    ages = [30, 25, 40, 22, 28]
    sizes = [16, 0, 1024, MAX_ALLOC, MAX_ALLOC + 1]

    for i in range(5):
        try:
            p = allocate_person(names[i], ages[i])
            print(f"Created: {p}")
        except Exception as e:
            print(f"Person alloc failed: {e}")

        try:
            mem = allocate_memory(sizes[i])
            if len(mem) >= 2:
                mem[0] = i & 0xFF
                mem[1] = (i * 2) & 0xFF
            print(f"Memory: {_preview(mem)}")
        except Exception as e:
            print(f"Memory alloc failed: {e}")

if __name__ == "__main__":
    main()