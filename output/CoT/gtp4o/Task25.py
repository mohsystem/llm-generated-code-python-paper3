from typing import List, Optional

def number(lines: Optional[List[str]]) -> List[str]:
    if lines is None:
        return []
    return [f"{i + 1}: {str(s)}" for i, s in enumerate(lines)]

if __name__ == "__main__":
    # Test case 1: Empty list
    t1 = []
    print(number(t1))

    # Test case 2: ["a", "b", "c"]
    t2 = ["a", "b", "c"]
    print(number(t2))

    # Test case 3: ["", "foo", "bar"]
    t3 = ["", "foo", "bar"]
    print(number(t3))

    # Test case 4: ["hello world", "Line 2"]
    t4 = ["hello world", "Line 2"]
    print(number(t4))

    # Test case 5: ["multiple", "lines", "with", "numbers", "10"]
    t5 = ["multiple", "lines", "with", "numbers", "10"]
    print(number(t5))