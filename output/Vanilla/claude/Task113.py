
def concatenate_strings(strings):
    result = ""
    for string in strings:
        result += string
    return result

if __name__ == "__main__":
    # Test case 1
    test1 = ["Hello", " ", "World"]
    print("Test 1:", concatenate_strings(test1))
    
    # Test case 2
    test2 = ["Java", "Programming", "Language"]
    print("Test 2:", concatenate_strings(test2))
    
    # Test case 3
    test3 = ["One", "Two", "Three", "Four"]
    print("Test 3:", concatenate_strings(test3))
    
    # Test case 4
    test4 = ["", "Empty", "", "Strings"]
    print("Test 4:", concatenate_strings(test4))
    
    # Test case 5
    test5 = ["Single"]
    print("Test 5:", concatenate_strings(test5))
