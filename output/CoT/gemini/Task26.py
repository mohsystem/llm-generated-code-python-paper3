def find_it(seq):
    result = 0
    for num in seq:
        result ^= num
    return result

if __name__ == '__main__':
    # Test cases
    print(find_it([7]))  # Output: 7
    print(find_it([0]))  # Output: 0
    print(find_it([1, 1, 2]))  # Output: 2
    print(find_it([0, 1, 0, 1, 0]))  # Output: 0
    print(find_it([1, 2, 2, 3, 3, 3, 4, 3, 3, 3, 2, 2, 1]))  # Output: 4