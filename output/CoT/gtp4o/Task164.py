from typing import List

def _last_name(name: str) -> str:
    if name is None:
        return ""
    s = name.strip()
    idx = s.rfind(" ")
    return s if idx == -1 else s[idx+1:]

def lastNameLensort(names: List[str]) -> List[str]:
    if names is None:
        return []
    # Key: length of last name, then last name case-insensitive, then last name (case) for deterministic tie-break
    return sorted(names, key=lambda n: (len(_last_name(n)), _last_name(n).lower(), _last_name(n)))

def _print(lst: List[str]) -> None:
    print(lst)

if __name__ == "__main__":
    # Test case 1
    t1 = [
        "Jennifer Figueroa",
        "Heather Mcgee",
        "Amanda Schwartz",
        "Nicole Yoder",
        "Melissa Hoffman"
    ]
    _print(lastNameLensort(t1))

    # Test case 2
    t2 = [
        "John Smith",
        "Amy Brown",
        "Zoey Clark",
        "Evan White",
        "Liam Jones"
    ]
    _print(lastNameLensort(t2))

    # Test case 3
    t3 = [
        "Alice   van Helsing",
        "Bob de la Cruz",
        "  Carla   Delaney ",
        "Derek O'Neill",
        "Eve   Stone  "
    ]
    _print(lastNameLensort(t3))

    # Test case 4
    t4 = ["Solo Person"]
    _print(lastNameLensort(t4))

    # Test case 5
    t5 = [
        "Ann Lee",
        "Ben Lee",
        "Cara Zee",
        "Dan Lee",
        "Eli Zee"
    ]
    _print(lastNameLensort(t5))