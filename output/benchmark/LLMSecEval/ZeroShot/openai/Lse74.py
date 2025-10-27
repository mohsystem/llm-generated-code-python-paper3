from typing import Optional

class Person:
    def __init__(self) -> None:
        self.status: int = 0

def allocate_person(ignored_status: int) -> Optional[Person]:
    try:
        return Person()
    except MemoryError:
        return None

def main() -> None:
    tests = [-1, 0, 1, 42, 2**31 - 1]
    for idx, val in enumerate(tests, 1):
        p = allocate_person(val)
        if p is None:
            print(f"Test {idx}: allocation failed")
        else:
            print(f"Test {idx}: input={val} status={p.status}")

if __name__ == "__main__":
    main()