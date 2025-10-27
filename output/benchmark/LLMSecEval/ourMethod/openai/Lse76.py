from dataclasses import dataclass
from typing import Optional

MAX_NAME_LEN = 64

@dataclass
class Person:
    name: str
    age: int
    status: int = 0  # initialized to 0 as required

def _sanitize_name(name: Optional[str]) -> str:
    if not isinstance(name, str):
        return ""
    trimmed = name.strip()
    if len(trimmed) > MAX_NAME_LEN:
        trimmed = trimmed[:MAX_NAME_LEN]
    return trimmed

def _sanitize_age(age: int) -> int:
    if not isinstance(age, int):
        return 0
    if age < 0:
        return 0
    if age > 150:
        return 150
    return age

def allocate_person(name: Optional[str], age: int) -> Person:
    safe_name = _sanitize_name(name)
    safe_age = _sanitize_age(age)
    # status is set to 0 by default as per dataclass field default
    return Person(name=safe_name, age=safe_age, status=0)

def main() -> None:
    # 5 test cases
    p1 = allocate_person("Alice", 30)
    p2 = allocate_person(" Bob  ", -5)
    p3 = allocate_person(None, 151)
    p4 = allocate_person("ThisNameIsWayTooLongAndShouldBeTruncatedAtSixtyFourCharacters_ABCDEFGHIJKLMNOPQRSTUVWXYZ", 42)
    p5 = allocate_person("   ", 0)

    print(p1)
    print(p2)
    print(p3)
    print(p4)
    print(p5)

if __name__ == "__main__":
    main()