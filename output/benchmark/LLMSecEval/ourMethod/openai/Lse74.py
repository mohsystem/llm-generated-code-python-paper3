from dataclasses import dataclass

@dataclass
class Person:
    status: int = 0

def allocate_person() -> Person:
    # Allocate a new Person and ensure status is 0
    p = Person()
    p.status = 0
    return p

def main() -> None:
    # 5 test cases
    for i in range(1, 6):
        p = allocate_person()
        if p is None:
            raise SystemExit("Allocation failed")
        print(f"Test {i}: status={p.status}")

if __name__ == "__main__":
    main()