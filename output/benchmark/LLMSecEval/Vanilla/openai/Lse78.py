class Person:
    def __init__(self):
        self.status = 0

def allocate_memory(size: int):
    if size < 0:
        raise ValueError("size must be non-negative")
    return bytearray(size)

def allocate_person():
    return Person()

def main():
        sizes = [0, 1, 16, 1024, 65536]

        # 5 test cases for memory allocation
        for s in sizes:
            mem = allocate_memory(s)
            print("Allocated memory size:", len(mem))

        # 5 test cases for person allocation
        for _ in range(5):
            p = allocate_person()
            print("Person status:", p.status)

if __name__ == "__main__":
    main()