class Person:
    def __init__(self, status=0):
        self.status = status

    def __repr__(self):
        return f"Person(status={self.status})"


def allocate_person():
    # Allocates a new Person and sets status to 0
    return Person(0)


def main():
    # 5 test cases
    for _ in range(5):
        p = allocate_person()
        print(p)


if __name__ == "__main__":
    main()