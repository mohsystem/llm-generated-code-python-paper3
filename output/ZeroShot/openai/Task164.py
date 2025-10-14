from typing import List, Optional

def lastNameLensort(names: Optional[List[Optional[str]]]) -> List[str]:
    if names is None:
        return []
    def last_name(s: Optional[str]) -> str:
        if s is None:
            return ""
        tokens = s.split()
        return tokens[-1] if tokens else ""
    def safe(s: Optional[str]) -> str:
        return "" if s is None else s
    return sorted([safe(x) for x in names],
                  key=lambda x: (len(last_name(x)), last_name(x).lower(), x.lower()))

if __name__ == "__main__":
    # Test case 1 (given example)
    t1 = [
        "Jennifer Figueroa",
        "Heather Mcgee",
        "Amanda Schwartz",
        "Nicole Yoder",
        "Melissa Hoffman"
    ]
    print(lastNameLensort(t1))

    # Test case 2 (all same last-name length -> alphabetical by last name)
    t2 = ["Anna Zed", "Bob Kay", "Cara May", "Dan Ray"]
    print(lastNameLensort(t2))

    # Test case 3 (extra spaces and punctuation)
    t3 = ["  John   Doe  ", "Alice   Smith", "Bob  O'Niel"]
    print(lastNameLensort(t3))

    # Test case 4 (same last name -> fall back to full name alphabetical)
    t4 = ["Cindy Lee", "Anna Lee", "Brian Lee"]
    print(lastNameLensort(t4))

    # Test case 5 (edge cases: empty, None, single token)
    t5 = ["", None, "Single", "Mary Ann", "  "]
    print(lastNameLensort(t5))