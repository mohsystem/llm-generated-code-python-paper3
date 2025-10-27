def get_value_at_index(data_list, index):
    """
    Securely gets a value from a list at a given index with bounds checking.
    """
    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")
    if 0 <= index < len(data_list):
        return data_list[index]
    else:
        raise IndexError(f"Index {index} is out of bounds for list of size {len(data_list)}")

def main():
    """
    Main function with test cases.
    """
    data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    # 5 Test cases: valid middle, valid start, valid end, invalid negative, invalid positive
    test_indexes = [5, 0, 9, -1, 10]

    print("Testing in Python...")
    print("List:", data)
    for index in test_indexes:
        try:
            value = get_value_at_index(data, index)
            print(f"Test case index {index}: Success! Value is {value}")
        except (IndexError, TypeError) as e:
            print(f"Test case index {index}: Error! {e}")

if __name__ == "__main__":
    main()