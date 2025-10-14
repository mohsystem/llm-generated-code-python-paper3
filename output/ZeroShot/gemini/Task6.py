def find_uniq(arr):
    """
    Finds the unique number in a list where all other numbers are equal.
    The list is guaranteed to contain at least 3 numbers.
    """
    # Compare the first two elements. If they are different, the unique
    # number is one of them. The third element decides which one.
    if arr[0] != arr[1]:
        return arr[1] if arr[0] == arr[2] else arr[0]
    else:
        # If the first two are the same, this is the common number.
        # Iterate through the rest to find the different one.
        common_number = arr[0]
        for num in arr[2:]:
            if num != common_number:
                return num
    # The problem guarantees a unique number exists, so this part is unreachable.


def main():
    """ Main function to run test cases. """
    # Test Case 1
    arr1 = [1, 1, 1, 2, 1, 1]
    print(f"Test 1 Result: {find_uniq(arr1)}")

    # Test Case 2
    arr2 = [0, 0, 0.55, 0, 0]
    print(f"Test 2 Result: {find_uniq(arr2)}")

    # Test Case 3: Unique at the beginning
    arr3 = [3, 1, 1, 1, 1, 1]
    print(f"Test 3 Result: {find_uniq(arr3)}")

    # Test Case 4: Unique at the end
    arr4 = [4, 4, 4, 4, 3.5]
    print(f"Test 4 Result: {find_uniq(arr4)}")

    # Test Case 5: Negative numbers
    arr5 = [-1, -1, -1, -2, -1]
    print(f"Test 5 Result: {find_uniq(arr5)}")

if __name__ == '__main__':
    main()