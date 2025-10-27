class Person:
    def __init__(self, status: int = 0):
        self.status = status

def allocate_person():
    return Person(status=0)

def main():
        for i in range(1, 6):
            p = allocate_person()
            if p is None:
                print("Allocation failed")
            else:
                print(f"Test {i}: status={p.status}")

if __name__ == "__main__":
    main()