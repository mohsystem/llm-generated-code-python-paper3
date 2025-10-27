# Function that takes an integer index and returns the value at that index in the array
def get_value_at_index(index: int) -> int:
    arr = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    return arr[index]

if __name__ == "__main__":
    test_indexes = [0, 3, 5, 7, 9]
    for idx in test_indexes:
        value = get_value_at_index(idx)
        print(f"Index {idx} -> Value: {value}")