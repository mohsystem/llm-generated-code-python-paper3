from typing import List

def find_uniq(arr: List[float]) -> float:
    """
    Finds the unique number in a list where all other numbers are the same.
    The list is guaranteed to have at least 3 numbers.
    """
    # The array is guaranteed to have at least 3 elements.
    # We compare the first three elements to determine the common number.
    if arr[0] != arr[1]:
        # If the first two are different, the third element reveals the common one.
        if arr[0] == arr[2]:
            return arr[1]
        else:
            return arr[0]
    else:
        # If the first two are the same, this is the common number.
        common_number = arr[0]
        # Iterate from the third element to find the unique one.
        for number in arr[2:]:
            if number != common_number:
                return number
    # This part is unreachable under the problem's guarantees.
    return 0.0

if __name__ == '__main__':
    # Test cases
    print(find_uniq([1, 1, 1, 2, 1, 1]))
    print(find_uniq([0, 0, 0.55, 0, 0]))
    print(find_uniq([3, 10, 3, 3, 3]))
    print(find_uniq([5, 5, 5, 5, 0.2]))
    print(find_uniq([-2, -2, -2, -1, -2]))