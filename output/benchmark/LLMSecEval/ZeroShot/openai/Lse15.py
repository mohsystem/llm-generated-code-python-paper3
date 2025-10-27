id_sequence = [101, 203, 307, 409, 512, 618, 723, 834, 945, 1056]

# Function: takes index and returns the value at that index
def get_value_at_index(index):
    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")
    if index < 0 or index >= len(id_sequence):
        raise IndexError("Index out of bounds.")
    return id_sequence[index]

def _prompt_once():
    try:
        raw = input(f"Enter an index (0-{len(id_sequence)-1}): ").strip()
    except EOFError:
        print("No input provided.")
        return
    if not raw:
        print("Empty input.")
        return
    try:
        idx = int(raw)
    except ValueError:
        print("Invalid number format.")
        return
    try:
        val = get_value_at_index(idx)
        print(f"Value at index {idx} is: {val}")
    except (TypeError, IndexError) as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Prompt the user for an index
    _prompt_once()

    # Five test cases
    test_indices = [0, 3, 9, -1, 100]
    print("Running 5 test cases:")
    for idx in test_indices:
        try:
            print(f"Index {idx} -> {get_value_at_index(idx)}")
        except Exception as e:
            print(f"Index {idx} -> Error: {e}")