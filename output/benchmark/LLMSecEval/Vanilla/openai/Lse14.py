def get_value_at_index(id_sequence, index):
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    return -1  # invalid index

if __name__ == "__main__":
    id_sequence = [10, 20, 30, 40, 50, 60, 70]
    try:
        user_index = int(input("Enter index: "))
    except:
        user_index = -1

    test_indices = [user_index, 0, 3, 6, -1]
    for idx in test_indices:
        print(get_value_at_index(id_sequence, idx))