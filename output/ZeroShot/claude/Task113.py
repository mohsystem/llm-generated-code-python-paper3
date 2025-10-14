
def concatenate_strings(strings):
    if strings is None or len(strings) == 0:
        return ""
    
    result = ""
    for s in strings:
        if s is not None:
            result += s
    return result


def main():
    # Test case 1: Multiple strings
    test1 = ["Hello", " ", "World", "!"]
    print("Test 1:", concatenate_strings(test1))
    
    # Test case 2: Empty list
    test2 = []
    print("Test 2:", concatenate_strings(test2))
    
    # Test case 3: Single string
    test3 = ["SingleString"]
    print("Test 3:", concatenate_strings(test3))
    
    # Test case 4: Strings with numbers and special characters
    test4 = ["Python", "123", "@#$", "Test"]
    print("Test 4:", concatenate_strings(test4))
    
    # Test case 5: Strings with None values
    test5 = ["Start", None, "Middle", None, "End"]
    print("Test 5:", concatenate_strings(test5))
    
    # Interactive user input
    print("\\nEnter number of strings to concatenate:")
    try:
        n = int(input())
        user_strings = []
        print(f"Enter {n} strings:")
        for i in range(n):
            user_strings.append(input())
        
        print("Result:", concatenate_strings(user_strings))
    except ValueError:
        print("Invalid input")


if __name__ == "__main__":
    main()
