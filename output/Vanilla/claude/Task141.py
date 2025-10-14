
def reverse_string(input_str):
    if input_str is None:
        return None
    return input_str[::-1]

if __name__ == "__main__":
    # Test case 1
    test1 = "Hello"
    print(f"Input: {test1}")
    print(f"Output: {reverse_string(test1)}")
    print()
    
    # Test case 2
    test2 = "12345"
    print(f"Input: {test2}")
    print(f"Output: {reverse_string(test2)}")
    print()
    
    # Test case 3
    test3 = "A man a plan a canal Panama"
    print(f"Input: {test3}")
    print(f"Output: {reverse_string(test3)}")
    print()
    
    # Test case 4
    test4 = ""
    print(f"Input: \"{test4}\"")
    print(f"Output: \"{reverse_string(test4)}\"")
    print()
    
    # Test case 5
    test5 = "Reverse Me!"
    print(f"Input: {test5}")
    print(f"Output: {reverse_string(test5)}")
