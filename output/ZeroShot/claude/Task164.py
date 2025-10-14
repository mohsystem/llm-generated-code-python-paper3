
def lastNameLensort(names):
    if not names:
        return names
    
    def get_last_name(name):
        return name.split()[-1]
    
    return sorted(names, key=lambda x: (len(get_last_name(x)), get_last_name(x)))

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
    test2 = [
        "John Smith",
        "Jane Doe",
        "Bob Lee"
    ]
    print("Test 2:", lastNameLensort(test2))
    
    # Test case 3
    test3 = [
        "Alice Johnson",
        "Charlie Brown",
        "David Anderson"
    ]
    print("Test 3:", lastNameLensort(test3))
    
    # Test case 4
    test4 = [
        "Emily White",
        "Michael Black",
        "Sarah Green"
    ]
    print("Test 4:", lastNameLensort(test4))
    
    # Test case 5
    test5 = [
        "Tom Martinez",
        "Lisa Garcia",
        "Kevin Rodriguez"
    ]
    print("Test 5:", lastNameLensort(test5))
