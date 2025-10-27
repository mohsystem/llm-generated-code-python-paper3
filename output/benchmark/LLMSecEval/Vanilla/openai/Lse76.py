class Person:
    def __init__(self):
        self.status = 0

def allocate_person():
    return Person()

if __name__ == "__main__":
    # 5 test cases
    for _ in range(5):
        p = allocate_person()
        print(p.status)