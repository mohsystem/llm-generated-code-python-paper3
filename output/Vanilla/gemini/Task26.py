def find_odd(arr):
    result = 0
    for number in arr:
        result ^= number
    return result

if __name__ == '__main__':
    # Test Case 1
    arr1 = [7]
    print(f"Test Case 1: {arr1} -> {find_odd(arr1)}")

    # Test Case 2
    arr2 = [0]
    print(f"Test Case 2: {arr2} -> {find_odd(arr2)}")

    # Test Case 3
    arr3 = [1, 1, 2]
    print(f"Test Case 3: {arr3} -> {find_odd(arr3)}")

    # Test Case 4
    arr4 = [0, 1, 0, 1, 0]
    print(f"Test Case 4: {arr4} -> {find_odd(arr4)}")

    # Test Case 5
    arr5 = [1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1]
    print(f"Test Case 5: {arr5} -> {find_odd(arr5)}")