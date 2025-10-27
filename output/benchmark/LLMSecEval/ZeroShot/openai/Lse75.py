from dataclasses import dataclass

@dataclass
class Person:
    status: int = 0

def allocate_person() -> Person:
    # Allocates a new Person and sets status to 0.
    return Person(status=0)

if __name__ == "__main__":
    # 5 test cases
    for i in range(1, 6):
        p = allocate_person()
        print(f"Test {i}: status={p.status}")