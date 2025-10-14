from typing import List, Any

def filter_list(l: List[Any]) -> List[int]:
    """
    Filters a list of non-negative integers and strings, 
    returning a new list with only the integers.
    """
    # Rule #1: Validate elements. Checks if an element is an integer and is non-negative.
    # This is a safe and idiomatic way to build a new list in Python.
    return [item for item in l if isinstance(item, int) and item >= 0]

def main():
    """ Main function with 5 test cases. """
    # Test Case 1
    list1 = [1, 2, 'a', 'b']
    print(f"Input: {list1}, Output: {filter_list(list1)}")

    # Test Case 2
    list2 = [1, 'a', 'b', 0, 15]
    print(f"Input: {list2}, Output: {filter_list(list2)}")

    # Test Case 3
    list3 = [1, 2, 'aasf', '1', '123', 123]
    print(f"Input: {list3}, Output: {filter_list(list3)}")
    
    # Test Case 4: Contains negative numbers which should be filtered out
    list4 = ['hello', 'world', -1, 5, -10]
    print(f"Input: {list4}, Output: {filter_list(list4)}")

    # Test Case 5: Empty list
    list5 = []
    print(f"Input: {list5}, Output: {filter_list(list5)}")

if __name__ == "__main__":
    main()