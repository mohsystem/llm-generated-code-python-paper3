from typing import List

def find_missing_number(nums: List[int]) -> int:
    """
    Finds the missing number in a list containing unique integers from 1 to n.

    Args:
        nums: A list of unique integers from 1 to n with one number missing.

    Returns:
        The missing number.
    """
    # According to the problem description, the input is a list of unique
    # integers from 1 to n, with one number missing. This means the list
    # will have a size of n-1.

    # If the list is empty, it means n=1, the full sequence is {1},
    # and the missing number is 1.
    if not nums:
        return 1

    # The full sequence should contain n numbers. The given list has n-1.
    # So, n is the list length + 1.
    n = len(nums) + 1

    # Python's integers handle arbitrary size, so overflow is not an issue.
    # Formula for sum of first n natural numbers: n * (n + 1) / 2
    expected_sum = n * (n + 1) // 2

    # The built-in sum() is a safe and efficient way to sum the elements.
    actual_sum = sum(nums)

    # The difference is the missing number.
    return expected_sum - actual_sum

if __name__ == '__main__':
    # 5 test cases
    test1 = [1, 2, 4, 5]  # n=5, missing 3
    print(f"Test 1: Array={test1}, Missing={find_missing_number(test1)}")

    test2 = [2, 3, 1, 5]  # n=5, missing 4
    print(f"Test 2: Array={test2}, Missing={find_missing_number(test2)}")

    test3 = [1]  # n=2, missing 2
    print(f"Test 3: Array={test3}, Missing={find_missing_number(test3)}")

    test4 = []  # n=1, missing 1
    print(f"Test 4: Array={test4}, Missing={find_missing_number(test4)}")

    test5 = [1, 2, 3, 4, 5, 6, 7, 9, 10]  # n=10, missing 8
    print(f"Test 5: Array={test5}, Missing={find_missing_number(test5)}")