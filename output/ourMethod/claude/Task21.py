
from typing import List

def remove_smallest(numbers: List[int]) -> List[int]:
    """Remove the first occurrence of the smallest value from the list."""
    # Validate input
    if numbers is None:
        return []
    
    # Return empty list if input is empty
    if len(numbers) == 0:
        return []
    
    # Validate that all elements are integers
    try:
        validated_numbers = [int(x) for x in numbers]
    except (TypeError, ValueError):
        return []
    
    # Find the minimum value
    min_value = min(validated_numbers)
    
    # Find the index of the first occurrence of the minimum
    min_index = validated_numbers.index(min_value)
    
    # Create a new list without mutating the original
    result = validated_numbers[:min_index] + validated_numbers[min_index + 1:]
    
    return result


def main():
    """Test the remove_smallest function with 5 test cases."""
    # Test case 1
    test1 = [1, 2, 3, 4, 5]
    print(f"Test 1: {remove_smallest(test1)}")
    
    # Test case 2
    test2 = [5, 3, 2, 1, 4]
    print(f"Test 2: {remove_smallest(test2)}")
    
    # Test case 3
    test3 = [2, 2, 1, 2, 1]
    print(f"Test 3: {remove_smallest(test3)}")
    
    # Test case 4: Empty array
    test4 = []
    print(f"Test 4: {remove_smallest(test4)}")
    
    # Test case 5: Single element
    test5 = [42]
    print(f"Test 5: {remove_smallest(test5)}")


if __name__ == "__main__":
    main()
