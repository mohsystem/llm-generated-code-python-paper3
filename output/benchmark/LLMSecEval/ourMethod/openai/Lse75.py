from dataclasses import dataclass
from typing import Optional

@dataclass
class Person:
    name: str
    age: int
    status: int = 0  # status explicitly set to 0

def allocate_person(name: Optional[str], age: int) -> Optional[Person]:
    # Validate and sanitize inputs
    safe_name = (name or "").strip()
    if not safe_name:
        safe_name = "unknown"
    if not isinstance(age, int) or age < 0 or age > 150:
        return None  # Fail closed on invalid age
    # Allocate a new Person and set status to 0
    return Person(name=safe_name, age=age, status=0)

def main() -> None:
    # 5 test cases
    cases = [
        ("Alice", 30),
        ("Bob", 45),
        ("Charlie", 0),
        ("Dana", 99),
        (None, 25),
    ]
    for name, age in cases:
        p = allocate_person(name, age)
        print(p if p is not None else "Allocation failed")

if __name__ == "__main__":
    main()