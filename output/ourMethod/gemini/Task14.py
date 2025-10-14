from typing import List

def find_even_index(arr: List[int]) -> int:
    """
    Finds an index N in a list of integers where the sum of the integers
    to the left of N is equal to the sum of the integers to the right of N.
    
    Args:
        arr: A list of integers.
    
    Returns:
        The lowest index N where the left side sum equals the right side sum.
        Returns -1 if no such index is found.
    """
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
    test1 = [1, 2, 3, 4, 3, 2, 1]
    print(f"Input: {test1}, Output: {find_even_index(test1)}")

    # Test Case 2
    test2 = [1, 100, 50, -51, 1, 1]
    print(f"Input: {test2}, Output: {find_even_index(test2)}")

    # Test Case 3
    test3 = [20, 10, -80, 10, 10, 15, 35]
    print(f"Input: {test3}, Output: {find_even_index(test3)}")

    # Test Case 4: index is at the end
    test4 = [10, -80, 10, 10, 15, 35, 20]
    print(f"Input: {test4}, Output: {find_even_index(test4)}")

    # Test Case 5: no solution
    test5 = [1, 2, 3, 4, 5, 6]
    print(f"Input: {test5}, Output: {find_even_index(test5)}")