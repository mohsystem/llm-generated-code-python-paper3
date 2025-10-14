
def lastNameLensort(names):
    if not names:
        return names
    
    def get_last_name(name):
        return name.split()[-1]
    
    return sorted(names, key=lambda name: (len(get_last_name(name)), get_last_name(name)))

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
        "John Doe",
        "Jane Smith",
        "Bob Lee"
    ]
    print("Test 2:", lastNameLensort(test2))
    
    # Test case 3
    test3 = [
        "Alice Johnson",
        "Charlie Brown",
        "David Green"
    ]
    print("Test 3:", lastNameLensort(test3))
    
    # Test case 4
    test4 = [
        "Emily White",
        "Frank Black",
        "Grace Blue"
    ]
    print("Test 4:", lastNameLensort(test4))
    
    # Test case 5
    test5 = [
        "Michael Anderson",
        "Sarah Williams",
        "Tom Martinez"
    ]
    print("Test 5:", lastNameLensort(test5))
