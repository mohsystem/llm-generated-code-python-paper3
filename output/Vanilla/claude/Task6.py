
def find_uniq(arr):
    # Compare first three elements to determine which is unique
    if arr[0] == arr[1]:
        # arr[0] is the common element
        common = arr[0]
        for num in arr:
            if num != common:
                return num
    elif arr[0] == arr[2]:
        # arr[0] is the common element, arr[1] is unique
        return arr[1]
    else:
        # arr[1] or arr[2] is the common element, arr[0] is unique
        return arr[0]

if __name__ == "__main__":
    # Test case 1
    print(find_uniq([1, 1, 1, 2, 1, 1]))  # => 2
    
    # Test case 2
    print(find_uniq([0, 0, 0.55, 0, 0]))  # => 0.55
    
    # Test case 3
    print(find_uniq([3, 3, 3, 3, 5]))  # => 5
    
    # Test case 4
    print(find_uniq([10, 9, 9, 9, 9]))  # => 10
    
    # Test case 5
    print(find_uniq([7.5, 7.5, 8.5, 7.5]))  # => 8.5
