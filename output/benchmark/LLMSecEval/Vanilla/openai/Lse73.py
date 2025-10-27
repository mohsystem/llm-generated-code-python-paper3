from ctypes import Structure, c_char, c_int, c_double, sizeof, POINTER, pointer

class Person(Structure):
    _fields_ = [
        ("name", c_char * 50),
        ("age", c_int),
        ("height", c_double),
    ]

def allocate_person():
    # Allocates a block of memory of size sizeof(Person) and returns a pointer to it
    p = Person()  # this allocates sizeof(Person)
    return pointer(p)

def set_person(p_ptr: POINTER(Person), name: bytes, age: int, height: float):
    # name should be bytes; will be truncated if longer than 49 to keep null terminator
    max_len = 49
    p_ptr.contents.name[:len(name[:max_len])] = name[:max_len]
    p_ptr.contents.name[len(name[:max_len])] = 0  # ensure null-termination
    p_ptr.contents.age = age
    p_ptr.contents.height = height

def person_to_str(p_ptr: POINTER(Person)) -> str:
    # Build string from contents
    raw_name = bytes(p_ptr.contents.name)
    end = raw_name.find(b'\x00')
    if end == -1:
        end = len(raw_name)
    name = raw_name[:end].decode('utf-8', errors='ignore')
    return f"Person(name='{name}', age={p_ptr.contents.age}, height={p_ptr.contents.height}, size={sizeof(Person)})"

def main():
    # 5 test cases
    p1 = allocate_person()
    set_person(p1, b"Alice", 30, 1.65)
    print(person_to_str(p1))

    p2 = allocate_person()
    set_person(p2, b"Bob", 25, 1.80)
    print(person_to_str(p2))

    p3 = allocate_person()
    set_person(p3, b"Carol", 40, 1.70)
    print(person_to_str(p3))

    p4 = allocate_person()
    set_person(p4, b"Dave", 35, 1.75)
    print(person_to_str(p4))

    p5 = allocate_person()
    set_person(p5, b"Eve", 28, 1.60)
    print(person_to_str(p5))

if __name__ == "__main__":
    main()