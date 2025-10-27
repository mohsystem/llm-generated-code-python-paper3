class Person:
    def __init__(self, name: str, status: int):
        self.name = name
        self.status = status

    def __repr__(self):
        return f"Person(name='{self.name}', status={self.status})"


def alloc(size: int) -> bytearray:
    if size < 0:
        raise ValueError("size must be non-negative")
    return bytearray(size)


def create_person(name: str, status: int) -> Person:
    return Person(name, status)


def main():
    sizes = [8, 16, 32, 64, 128]  # 5 test cases
    bufs = [alloc(s) for s in sizes]
    print("Allocated buffers lengths:", [len(b) for b in bufs])

    john = create_person("John", 0)
    print("Created person:", john)

    # Additional small validations
    b = alloc(5)
    for i in range(len(b)):
        b[i] = i + 1
    print("Sample buffer contents:", list(b))


if __name__ == "__main__":
    main()