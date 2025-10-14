from typing import List

def find_missing_letter(chars: List[str]) -> str:
    """
    Finds the missing letter in a list of consecutive (increasing) letters.

    :param chars: A list of consecutive letters with one letter missing.
    :return: The missing letter.
    """
    for i in range(1, len(chars)):
        # Check if the ASCII value of the current char is not one more than the previous
        if ord(chars[i]) != ord(chars[i-1]) + 1:
            # If not, the missing character is the one after the previous character
            return chr(ord(chars[i-1]) + 1)
    
    # This part should be unreachable given the problem constraints
    # (always exactly one letter missing in a list of length >= 2).
    return ""

def main():
    """Main function with test cases."""
    # Test Case 1
    test1 = ['a','b','c','d','f']
    print(f"Test 1: {test1} -> {find_missing_letter(test1)}")

    # Test Case 2
    test2 = ['O','Q','R','S']
    print(f"Test 2: {test2} -> {find_missing_letter(test2)}")

    # Test Case 3
    test3 = ['x', 'z']
    print(f"Test 3: {test3} -> {find_missing_letter(test3)}")

    # Test Case 4
    test4 = ['A', 'B', 'D']
    print(f"Test 4: {test4} -> {find_missing_letter(test4)}")

    # Test Case 5
    test5 = ['m', 'n', 'o', 'q', 'r']
    print(f"Test 5: {test5} -> {find_missing_letter(test5)}")

if __name__ == "__main__":
    main()