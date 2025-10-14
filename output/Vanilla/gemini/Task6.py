def find_uniq(arr):
    # Since the array is guaranteed to have at least 3 elements,
    # we can check the first three to determine the unique number.
    if arr[0] != arr[1]:
        # If the first two are different, one of them is the unique number.
        # The third element will tell us which one is the common number.
        if arr[0] == arr[2]:
            return arr[1]  # arr[1] is unique
        else:
            return arr[0]  # arr[0] is unique
    else:
        # The first two numbers are the same, so this is the common number.
        # We iterate through the rest of the array to find the different one.
        common_number = arr[0]
        for num in arr[2:]:
            if num != common_number:
                return num
    # This part should not be reachable given the problem constraints
    return None

if __name__ == '__main__':
    # Test cases
    print(find_uniq([1, 1, 1, 2, 1, 1]))
    print(find_uniq([0, 0, 0.55, 0, 0]))
    print(find_uniq([3, 10, 3, 3, 3]))
    print(find_uniq([5, 5, 5, 5, 4]))
    print(find_uniq([8, 8, 8, 8, 8, 8, 8, 7]))