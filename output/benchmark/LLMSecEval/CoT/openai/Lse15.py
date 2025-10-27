# Chain-of-Through process:
# 1) Problem understanding: Function prompts user for an index and returns the value at that index from id_sequence.
# 2) Security requirements: Validate input type and bounds; handle EOF/invalid input robustly.
# 3) Secure coding generation: Use safe parsing, loops, and bounds checks; never index without validation.
# 4) Code review: Ensure no unchecked indexing; handle EOF and bad input gracefully.
# 5) Secure code output: Provide final, validated version.

ID_SEQUENCE = [101, 202, 303, 404, 505, 606, 707, 808, 909, 1001]

def get_value_at_index(index_param: int) -> int:
    """
    Prompts the user for an index and returns the corresponding value from ID_SEQUENCE.
    Returns -1 if EOF or unrecoverable input issue is encountered.
    """
    while True:
        try:
            line = input(f"Enter index (0..{len(ID_SEQUENCE)-1}): ").strip()
        except EOFError:
            return -1
        if not line:
            print("Invalid input: empty. Please enter an integer index.")
            continue
        try:
            idx = int(line, 10)
        except ValueError:
            print("Invalid input: not an integer. Try again.")
            continue
        if idx < 0 or idx >= len(ID_SEQUENCE):
            print(f"Index out of bounds. Valid range is 0..{len(ID_SEQUENCE)-1}. Try again.")
            continue
        return ID_SEQUENCE[idx]

if __name__ == "__main__":
    # 5 test cases; function will prompt for index each time
    for t in range(1, 6):
        value = get_value_at_index(-1)
        print(f"Test {t} -> Value: {value}")