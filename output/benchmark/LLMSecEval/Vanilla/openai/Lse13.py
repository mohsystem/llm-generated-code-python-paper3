id_sequence = [101, 203, 305, 407, 509, 611, 713, 815, 917, 1020]

def get_value_at_index(index):
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    return -1  # Return -1 for invalid index

if __name__ == "__main__":
    # 5 test cases
    print("Running 5 test cases:")
    for idx in [0, 1, 4, 9, 10]:
        print(f"Index {idx} -> {get_value_at_index(idx)}")

    # Prompt user for input
    try:
        idx = int(input("Enter index: ").strip())
        print(get_value_at_index(idx))
    except:
        print("Invalid input")