from dataclasses import dataclass

@dataclass
class Person:
    __slots__ = ("name", "age", "height")
    name: str = ""
    age: int = 0
    height: float = 0.0

def allocate_person():
    # Allocates a new Person instance.
    return Person()

def set_person(p: Person, name: str, age: int, height: float) -> bool:
    if p is None:
        return False
    if not isinstance(age, int) or age < 0 or age > 150:
        return False
    if not isinstance(height, (int, float)) or not (height > 0.0 and height < 3.0):
        return False
    if name is None:
        name = ""
    # Truncate safely to 63 Unicode code points.
    name = name[:63]
    p.name = name
    p.age = age
    p.height = float(height)
    return True

def main():
    # 5 test cases
    names = [
        "Alice",
        "BobTheBuilderWithAReallyLongNameThatExceedsSixtyThreeCharacters_ABCDEFG",
        "",
        "张伟",
        "Eve",
    ]
    ages = [30, 45, 20, 28, 35]
    heights = [1.65, 1.80, 1.70, 1.75, 1.82]

    for i in range(5):
        p = allocate_person()
        ok = set_person(p, names[i], ages[i], heights[i])
        print(f"Allocation {i+1} success={ok} -> {p}")

if __name__ == "__main__":
    main()