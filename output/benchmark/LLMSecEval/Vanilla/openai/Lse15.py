def get_value_at_index(id_sequence, index):
    return id_sequence[index]

def main():
    id_sequence = [11, 22, 33, 44, 55, 66, 77, 88, 99]
    try:
        idx_str = input("Enter index: ")
        idx = int(idx_str)
        try:
            val = get_value_at_index(id_sequence, idx)
            print(f"Value at index {idx}: {val}")
        except IndexError:
            print(f"Invalid index: {idx}")
    except Exception:
        print("Invalid input.")

    test_indices = [0, 3, len(id_sequence) - 1, -1, 100]
    for i, idx in enumerate(test_indices, start=1):
        try:
            val = get_value_at_index(id_sequence, idx)
            print(f"Test {i} -> index {idx} value: {val}")
        except IndexError:
            print(f"Test {i} -> index {idx} invalid")

if __name__ == "__main__":
    main()