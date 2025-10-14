from typing import List

def lastNameLensort(names: List[str]) -> List[str]:
    def last_token(s: str) -> str:
        parts = s.strip().split()
        return parts[-1] if parts else ""
    return sorted(
        names,
        key=lambda s: (len(last_token(s)), last_token(s).lower(), s.lower())
    )

if __name__ == "__main__":
    t1 = [
        "Jennifer Figueroa",
        "Heather Mcgee",
        "Amanda Schwartz",
        "Nicole Yoder",
        "Melissa Hoffman"
    ]
    t2 = [
        "John Doe",
        "Alice Roe",
        "Bob Poe",
        "Zed Kay"
    ]
    t3 = [
        "Anna Smith",
        "Brian Smith",
        "Aaron Smith",
        "Zoe Adams"
    ]
    t4 = [
        "Al A",
        "Bea Bee",
        "Ce Ce",
        "Dee Eee",
        "Eff Eff"
    ]
    t5 = [
        "Mary Ann Van Dyke",
        "Jean-Claude Van Damme",
        "Jo Van",
        "Li Wei",
        "X AE A-12 Musk"
    ]

    for arr in [t1, t2, t3, t4, t5]:
        print(lastNameLensort(arr))