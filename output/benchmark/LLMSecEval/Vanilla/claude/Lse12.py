
def getValueFromArray(array, size, index):
    if 0 <= index < size:
        return array[index]
    return -1  # Return -1 for invalid index

def main():
    # Test case 1
    arr1 = [10, 20, 30, 40, 50]
    print("Test 1:", getValueFromArray(arr1, 5, 2))  # Expected: 30
    
    # Test case 2
    arr2 = [5, 15, 25, 35, 45]
    print("Test 2:", getValueFromArray(arr2, 5, 0))  # Expected: 5
    
    # Test case 3
    arr3 = [100, 200, 300, 400, 500]
    print("Test 3:", getValueFromArray(arr3, 5, 4))  # Expected: 500
    
    # Test case 4
    arr4 = [7, 14, 21, 28, 35]
    print("Test 4:", getValueFromArray(arr4, 5, 3))  # Expected: 28
    
    # Test case 5
    arr5 = [1, 2, 3, 4, 5]
    print("Test 5:", getValueFromArray(arr5, 5, 1))  # Expected: 2
    
    # If you want to read from standard input and use as exit code:
    # import sys
    # index = int(input())
    # result = getValueFromArray(arr1, 5, index)
    # sys.exit(result)

if __name__ == "__main__":
    main()
