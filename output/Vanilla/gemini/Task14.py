def find_even_index(arr):
    total_sum = sum(arr)
    left_sum = 0
    for i, num in enumerate(arr):
        # The right sum is the total sum minus the left sum and the current element
        right_sum = total_sum - left_sum - num
        if left_sum == right_sum:
            return i
        left_sum += num
    return -1

if __name__ == '__main__':
    # Test Case 1
    arr1 = [1, 2, 3, 4, 3, 2, 1]
    print(f"Array: {arr1} -> Index: {find_even_index(arr1)}")

    # Test Case 2
    arr2 = [1, 100, 50, -51, 1, 1]
    print(f"Array: {arr2} -> Index: {find_even_index(arr2)}")

    # Test Case 3
    arr3 = [20, 10, -80, 10, 10, 15, 35]
    print(f"Array: {arr3} -> Index: {find_even_index(arr3)}")
    
    # Test Case 4
    arr4 = [10, -80, 10, 10, 15, 35, 20]
    print(f"Array: {arr4} -> Index: {find_even_index(arr4)}")
    
    # Test Case 5
    arr5 = [1, 2, 3, 4, 5, 6]
    print(f"Array: {arr5} -> Index: {find_even_index(arr5)}")