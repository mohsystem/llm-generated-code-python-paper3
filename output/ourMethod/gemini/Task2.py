from typing import List

def create_phone_number(numbers: List[int]) -> str:
    """
    Formats a list of 10 integers (0-9) into a phone number string.

    Args:
        numbers: A list of 10 integers, where each integer is between 0 and 9.

    Returns:
        A string representing the phone number, e.g., "(123) 456-7890".

    Raises:
        ValueError: If the input list is not of length 10 or contains numbers
                    outside the 0-9 range.
    """
    if not isinstance(numbers, list) or len(numbers) != 10:
        raise ValueError("Input must be a list of exactly 10 integers.")
    
    if not all(isinstance(n, int) and 0 <= n <= 9 for n in numbers):
        raise ValueError("All elements in the list must be integers between 0 and 9.")
        
    return f"({numbers[0]}{numbers[1]}{numbers[2]}) {numbers[3]}{numbers[4]}{numbers[5]}-{numbers[6]}{numbers[7]}{numbers[8]}{numbers[9]}"

if __name__ == '__main__':
    # Test Case 1: Valid input
    test1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    print(f"Test 1: {test1}")
    print(f"Result: {create_phone_number(test1)}\n")
    
    # Test Case 2: Another valid input
    test2 = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    print(f"Test 2: {test2}")
    print(f"Result: {create_phone_number(test2)}\n")

    # Test Case 3: Invalid length (too long)
    test3 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1]
    print(f"Test 3: {test3}")
    try:
        create_phone_number(test3)
    except ValueError as e:
        print(f"Caught expected exception: {e}\n")

    # Test Case 4: Invalid number (out of range)
    test4 = [1, 2, 3, 4, -5, 6, 7, 8, 9, 0]
    print(f"Test 4: {test4}")
    try:
        create_phone_number(test4)
    except ValueError as e:
        print(f"Caught expected exception: {e}\n")
    
    # Test Case 5: Invalid type in list
    test5 = [1, 2, 3, 4, 5, '6', 7, 8, 9, 0]
    print(f"Test 5: {test5}")
    try:
        create_phone_number(test5)
    except ValueError as e:
        print(f"Caught expected exception: {e}\n")