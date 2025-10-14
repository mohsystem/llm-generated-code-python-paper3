
from typing import List

def find_uniq(arr: List[float]) -> float:
    if arr is None or len(arr) < 3:
        raise ValueError("Array must contain at least 3 elements")
    
    a = arr[0]
    b = arr[1]
    c = arr[2]
    
    # If first two are equal, the unique is different from them
    if a == b:
        if a != c:
            return c
        # a == b == c, so unique must be later
        for i in range(3, len(arr)):
            if arr[i] != a:
                return arr[i]
    elif a == c:
        # a == c != b, so b is unique
        return b
    else:
        # b == c != a, so a is unique
        return a
    
    raise ValueError("No unique element found")


def main():
    # Test case 1
    print(find_uniq([1, 1, 1, 2, 1, 1]))  # 2
    
    # Test case 2
    print(find_uniq([0, 0, 0.55, 0, 0]))  # 0.55
    
    # Test case 3
    print(find_uniq([5, 5, 5, 5, 3]))  # 3
    
    # Test case 4
    print(find_uniq([10, 9, 9, 9, 9]))  # 10
    
    # Test case 5
    print(find_uniq([-1, -1, -1, 0, -1]))  # 0


if __name__ == "__main__":
    main()
