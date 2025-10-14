
def is_isogram(input_str: str) -> bool:
    if input_str is None:
        return False
    
    if len(input_str) == 0:
        return True
    
    # Validate input contains only letters
    if not input_str.isalpha():
        return False
    
    # Convert to lowercase and check for duplicates
    lowercase = input_str.lower()
    seen = set()
    
    for char in lowercase:
        if char in seen:
            return False
        seen.add(char)
    
    return True


def main():
    # Test case 1
    test1 = "Dermatoglyphics"
    print(f"{test1} --> {is_isogram(test1)}")
    
    # Test case 2
    test2 = "aba"
    print(f"{test2} --> {is_isogram(test2)}")
    
    # Test case 3
    test3 = "moOse"
    print(f"{test3} --> {is_isogram(test3)}")
    
    # Test case 4
    test4 = ""
    print(f'"{test4}" --> {is_isogram(test4)}')
    
    # Test case 5
    test5 = "isogram"
    print(f"{test5} --> {is_isogram(test5)}")


if __name__ == "__main__":
    main()
