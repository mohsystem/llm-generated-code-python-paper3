from typing import Optional

MAX_ALLOC = 1024 * 1024  # 1 MiB cap
MAX_NAME_LEN = 256


class Person:
    def __init__(self, name: str, status: int) -> None:
        self.name = name
        self.status = status

    def __repr__(self) -> str:
        return f"Person(name='{self.name}', status={self.status})"


def allocate_memory(size: int) -> Optional[bytearray]:
    if not isinstance(size, int):
        return None
    if size <= 0 or size > MAX_ALLOC:
        return None
    try:
        return bytearray(size)
    except MemoryError:
        return None


def create_person(name: Optional[str], status: int) -> Person:
    if name is None:
        name = "John"
    if not isinstance(name, str):
        name = str(name)
    if len(name) > MAX_NAME_LEN:
        name = name[:MAX_NAME_LEN]
    return Person(name=name, status=status)


if __name__ == "__main__":
    # 5 test cases
    a1 = allocate_memory(16)
    print("alloc 16 ok: {}".format(len(a1)) if a1 is not None else "alloc 16 failed")

    a2 = allocate_memory(0)
    print("alloc 0 ok: {}".format(len(a2)) if a2 is not None else "alloc 0 failed")

    a3 = allocate_memory(MAX_ALLOC)
    print("alloc MAX ok: {}".format(len(a3)) if a3 is not None else "alloc MAX failed")

    a4 = allocate_memory(MAX_ALLOC + 1)
    print("alloc MAX+1 ok: {}".format(len(a4)) if a4 is not None else "alloc MAX+1 failed")

    p = create_person("John", 0)
    print("person:", p)