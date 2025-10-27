def getValueFromArray(arr, size, index):
    # The size parameter is included as per the prompt's requirements,
    # though it is redundant in Python.
    return arr[index]

def main():
    id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    size = len(id_sequence)

    # 5 test cases
    test_indices = [0, 3, 5, 8, 9]
    
    for index in test_indices:
        value = getValueFromArray(id_sequence, size, index)
        print(f"Value at index {index} is {value}")

if __name__ == "__main__":
    main()