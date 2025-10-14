from typing import List

def posNegSort(arr: List[int]) -> List[int]:
    """
    Sorts the positive numbers in a list in ascending order,
    while keeping the negative numbers in their original positions.

    :param arr: The input list of integers.
    :return: A new list with positive numbers sorted.
    """
    if not arr:
        return []

    positives = sorted([x for x in arr if x > 0])

    pos_iter = iter(positives)

    result = [next(pos_iter) if x > 0 else x for x in arr]

    return result

if __name__ == '__main__':
    test_cases = [
        [6, 3, -2, 5, -8, 2, -2],
        [6, 5, 4, -1, 3, 2, -1, 1],
        [-5, -5, -5, -5, 7, -5],
        [],
        [1, -1, 2, -2, 3, -3]
    ]

    for arr in test_cases:
        print(f"Original: {arr}")
        result = posNegSort(arr)
        print(f"Sorted:   {result}")
        print()