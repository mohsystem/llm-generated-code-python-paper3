def find_uniq(arr):
    """
    Finds the unique number in an array where all other numbers are the same.
    The array is guaranteed to contain at least 3 numbers.
    """
    # If the first two numbers are different, one of them is the unique number.
    # We can check the third number to decide which one.
    if arr[0] != arr[1]:
        return arr[1] if arr[0] == arr[2] else arr[0]
    else:
        # If the first two numbers are the same, this is the common number.
        # We can then iterate through the rest of the array to find the different one.
        common_number = arr[0]
        for num in arr[2:]:
            if num != common_number:
                return num
    # This part should be unreachable given the problem constraints.
    return None

# Main block for testing
if __name__ == '__main__':
    # Test Case 1
    print(find_uniq([1, 1, 1, 2, 1, 1]))  # Expected: 2
    # Test Case 2
    print(find_uniq([0, 0, 0.55, 0, 0]))  # Expected: 0.55
    # Test Case 3
    print(find_uniq([3, 10, 3, 3, 3]))  # Expected: 10
    # Test Case 4
    print(find_uniq([5, 5, 5, 5, 4]))  # Expected: 4
    # Test Case 5
    print(find_uniq([8, 8, 8, 8, 8, 8, 8, 7]))  # Expected: 7