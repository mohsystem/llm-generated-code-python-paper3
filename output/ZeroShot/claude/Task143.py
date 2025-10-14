
def sort_array(arr):
    if arr is None or len(arr) == 0:
        return arr
    result = arr.copy()
    result.sort()
    return result

def main():
    # Test case 1: Regular array
    test1 = [5, 2, 8, 1, 9]
    print(f"Test 1: {sort_array(test1)}")
    
    # Test case 2: Already sorted array
    test2 = [1, 2, 3, 4, 5]
    print(f"Test 2: {sort_array(test2)}")
    
    # Test case 3: Reverse sorted array
    test3 = [9, 7, 5, 3, 1]
    print(f"Test 3: {sort_array(test3)}")
    
    # Test case 4: Array with duplicates
    test4 = [4, 2, 7, 2, 9, 4]
    print(f"Test 4: {sort_array(test4)}")
    
    # Test case 5: Single element array
    test5 = [42]
    print(f"Test 5: {sort_array(test5)}")

if __name__ == "__main__":
    main()
