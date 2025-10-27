class Person:
    def __init__(self):
        self.status = 0

def allocate_person():
    p = Person()
    p.status = 0
    return p

def main():
    # 5 test cases
    p1 = allocate_person()
    p2 = allocate_person()
    p3 = allocate_person()
    p4 = allocate_person()
    p5 = allocate_person()

    print(f"p1.status = {p1.status}")
    print(f"p2.status = {p2.status}")
    print(f"p3.status = {p3.status}")
    print(f"p4.status = {p4.status}")
    print(f"p5.status = {p5.status}")

if __name__ == "__main__":
    main()