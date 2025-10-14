
from typing import List, Any, Union


def filter_list(lst: List[Any]) -> List[int]:
    if lst is None:
        raise ValueError("Input list cannot be None")
    
    if not isinstance(lst, list):
        raise TypeError("Input must be a list")
    
    result = []
    
    for element in lst:
        if element is None:
            continue
        
        if isinstance(element, bool):
            continue
        
        if isinstance(element, int):
            if element >= 0:
                result.append(element)
    
    return result


def main():
    print("Test 1:", filter_list([1, 2, "a", "b"]))
    print("Test 2:", filter_list([1, "a", "b", 0, 15]))
    print("Test 3:", filter_list([1, 2, "a", "b", "aasf", "1", "123", 123]))
    print("Test 4:", filter_list([5, "test", 10, None, 20]))
    print("Test 5:", filter_list([100, 200, "xyz", 300]))


if __name__ == "__main__":
    main()
