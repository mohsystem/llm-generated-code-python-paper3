def getValueFromArray(arr, size, index):
    """
    Returns the value from an array at a given index.
    
    :param arr: The list of integers.
    :param size: The size of the list (included for signature consistency).
    :param index: The index of the element to retrieve.
    :return: The integer value at the specified index.
    """
    # Assuming the index is always within the valid bounds of the array.
    return arr[index]

def main():
    sample_array = [10, 20, 30, 40, 50]
    array_size = len(sample_array)

    # 5 Test Cases
    print("Python Test Cases:")
    
    # Test Case 1
    print(f"Value at index 0: {getValueFromArray(sample_array, array_size, 0)}")
    # Test Case 2
    print(f"Value at index 2: {getValueFromArray(sample_array, array_size, 2)}")
    # Test Case 3
    print(f"Value at index 4: {getValueFromArray(sample_array, array_size, 4)}")
    # Test Case 4
    print(f"Value at index 1: {getValueFromArray(sample_array, array_size, 1)}")
    # Test Case 5
    print(f"Value at index 3: {getValueFromArray(sample_array, array_size, 3)}")

if __name__ == "__main__":
    main()