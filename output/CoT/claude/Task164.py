
def lastNameLensort(names):
    if names is None:
        return []
    
    def extract_last_name(full_name):
        if not full_name or not isinstance(full_name, str):
            return ""
        trimmed = full_name.strip()
        if not trimmed:
            return ""
        parts = trimmed.rsplit(' ', 1)
        return parts[-1] if parts else ""
    
    def sort_key(name):
        last_name = extract_last_name(name)
        return (len(last_name), last_name)
    
    try:
        return sorted(names, key=sort_key)
    except Exception:
        return []


if __name__ == "__main__":
    # Test case 1
    test1 = [
        "Jennifer Figueroa",
        "Heather Mcgee",
        "Amanda Schwartz",
        "Nicole Yoder",
        "Melissa Hoffman"
    ]
    print("Test 1:", lastNameLensort(test1))
    
    # Test case 2
    test2 = ["John Doe", "Jane Smith", "Bob Lee"]
    print("Test 2:", lastNameLensort(test2))
    
    # Test case 3
    test3 = ["Alice Brown", "Charlie Brown", "David Green"]
    print("Test 3:", lastNameLensort(test3))
    
    # Test case 4 - Empty list
    test4 = []
    print("Test 4:", lastNameLensort(test4))
    
    # Test case 5 - Single name
    test5 = ["Michael Jackson"]
    print("Test 5:", lastNameLensort(test5))
