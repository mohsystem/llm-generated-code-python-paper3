import ctypes
from typing import Optional

class Person(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_int),
        ("name", ctypes.c_char * 32),
        ("salary", ctypes.c_double),
    ]

def allocate_person() -> ctypes.POINTER(Person):
    # Allocates a block of memory of size sizeof(person) and returns a pointer
    # Using ctypes ensures memory is appropriately sized and zero-initialized.
    p = Person()  # zero-initialized
    return ctypes.pointer(p)

def set_id(p: ctypes.POINTER(Person), value: int) -> None:
    if not p:
        raise ValueError("Invalid pointer")
    p.contents.id = int(value)

def get_id(p: ctypes.POINTER(Person)) -> int:
    if not p:
        raise ValueError("Invalid pointer")
    return int(p.contents.id)

def set_name(p: ctypes.POINTER(Person), name: Optional[str]) -> None:
    if not p:
        raise ValueError("Invalid pointer")
    raw = (name or "").encode("utf-8")
    raw = raw[:31]  # reserve space for NUL
    buf = raw + b"\x00" * (32 - len(raw))
    p.contents.name = buf

def get_name(p: ctypes.POINTER(Person)) -> str:
    if not p:
        raise ValueError("Invalid pointer")
    raw = bytes(p.contents.name)
    nul = raw.find(b"\x00")
    if nul != -1:
        raw = raw[:nul]
    return raw.decode("utf-8", errors="strict")

def set_salary(p: ctypes.POINTER(Person), salary: float) -> None:
    if not p:
        raise ValueError("Invalid pointer")
    p.contents.salary = float(salary)

def get_salary(p: ctypes.POINTER(Person)) -> float:
    if not p:
        raise ValueError("Invalid pointer")
    return float(p.contents.salary)

def sizeof_person() -> int:
    return ctypes.sizeof(Person)

def secure_zero_person(p: ctypes.POINTER(Person)) -> None:
    if not p:
        return
    addr = ctypes.addressof(p.contents)
    ctypes.memset(addr, 0, ctypes.sizeof(Person))

if __name__ == "__main__":
    # 5 test cases
    names = ["Alice", "Bob", "Carlos", "Diana", "Eve-LongName-ShouldBeTruncated"]
    ids = [1, 2, 3, 4, 5]
    salaries = [50000.0, 60000.5, 72000.75, 81000.0, 90500.25]

    print(f"sizeof(person) = {sizeof_person()} bytes")

    people = []
    for i in range(5):
        p = allocate_person()
        set_id(p, ids[i])
        set_name(p, names[i])
        set_salary(p, salaries[i])
        print(f"Test {i+1}: id={get_id(p)}, name=\"{get_name(p)}\", salary={get_salary(p)}")
        people.append(p)

    # Optional: zero memory for demonstration
    for p in people:
        secure_zero_person(p)