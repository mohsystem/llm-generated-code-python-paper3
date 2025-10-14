
from typing import Optional

def reverse_words(input_str: str) -> str:
    if input_str is None:
        raise ValueError("Input cannot be None")
    
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    
    # Validate input contains only letters and spaces
    if not all(c.isalpha() or c.isspace() for c in input_str):
        raise ValueError("Input must contain only letters and spaces")
    
    # Validate reasonable length to prevent DoS
    if len(input_str) > 10000:
        raise ValueError("Input exceeds maximum allowed length")
    
    words = input_str.split(' ')
    result = []
    
    for word in words:
        if len(word) >= 5:
            result.append(word[::-1])
        else:
            result.append(word)
    
    return ' '.join(result)


def main():
    # Test case 1
    test1 = "Hey fellow warriors"
    print(f'Input: "{test1}"')
    print(f'Output: "{reverse_words(test1)}"')
    print()
    
    # Test case 2
    test2 = "This is a test"
    print(f'Input: "{test2}"')
    print(f'Output: "{reverse_words(test2)}"')
    print()
    
    # Test case 3
    test3 = "This is another test"
    print(f'Input: "{test3}"')
    print(f'Output: "{reverse_words(test3)}"')
    print()
    
    # Test case 4
    test4 = "abcd"
    print(f'Input: "{test4}"')
    print(f'Output: "{reverse_words(test4)}"')
    print()
    
    # Test case 5
    test5 = "apple banana"
    print(f'Input: "{test5}"')
    print(f'Output: "{reverse_words(test5)}"')


if __name__ == "__main__":
    main()
