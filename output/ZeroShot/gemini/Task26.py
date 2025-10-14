def find_odd(arr):
    """
    Finds the integer that appears an odd number of times in an array.
    It uses the XOR bitwise operator. The property of XOR is that a^a = 0 and a^0 = a.
    When we XOR all numbers, pairs of identical numbers cancel out, leaving the unique one.
    :param arr: The input list of integers. There will always be only one integer
                that appears an odd number of times.
    :return: The integer that appears an odd number of times.
    """
    result = 0
    for number in arr:
        result ^= number
    return result

if __name__ == "__main__":
    # Test Case 1
    test1 = [7]
    print(f"Input: {test1}, Output: {find_odd(test1)}")

    # Test Case 2
    test2 = [0]
    print(f"Input: {test2}, Output: {find_odd(test2)}")

    # Test Case 3
    test3 = [1, 1, 2]
    print(f"Input: {test3}, Output: {find_odd(test3)}")

    # Test Case 4
    test4 = [0, 1, 0, 1, 0]
    print(f"Input: {test4}, Output: {find_odd(test4)}")

    # Test Case 5
    test5 = [1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1]
    print(f"Input: {test5}, Output: {find_odd(test5)}")