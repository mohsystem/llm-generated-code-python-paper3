
from typing import List

def last_name_lensort(names: List[str]) -> List[str]:
    if names is None:
        return []
    
    valid_names = [name for name in names if name and name.strip()]
    
    def extract_last_name(full_name: str) -> str:
        if not full_name or not full_name.strip():
            return ""
        trimmed = full_name.strip()
        last_space = trimmed.rfind(' ')
        if last_space > 0 and last_space < len(trimmed) - 1:
            return trimmed[last_space + 1:]
        return trimmed
    
    valid_names.sort(key=lambda name: (len(extract_last_name(name)), extract_last_name(name)))
    return valid_names


def main():
    # Test case 1
    test1 = [
        "Jennifer Figueroa",
        "Heather Mcgee",
        "Amanda Schwartz",
        "Nicole Yoder",
        "Melissa Hoffman"
    ]
    print("Test 1:", last_name_lensort(test1))
    
    # Test case 2
    test2 = [
        "John Doe",
        "Jane Smith",
        "Bob Lee"
    ]
    print("Test 2:", last_name_lensort(test2))
    
    # Test case 3
    test3 = [
        "Alice Anderson",
        "Charlie Brown",
        "David Clark"
    ]
    print("Test 3:", last_name_lensort(test3))
    
    # Test case 4
    test4 = [
        "Emma Wilson",
        "Olivia Moore"
    ]
    print("Test 4:", last_name_lensort(test4))
    
    # Test case 5
    test5 = [
        "Michael Johnson",
        "Sarah Williams",
        "James Davis"
    ]
    print("Test 5:", last_name_lensort(test5))


if __name__ == "__main__":
    main()
