import sys

id_sequence = [101, 203, 307, 409, 512, 678, 789, 890, 901, 1024]

def get_id_at_index(index: int) -> int:
    if index < 0 or index >= len(id_sequence):
        raise IndexError("Index out of bounds")
    return id_sequence[index]

def main():
    try:
        sys.stdout.write(f"Enter index (0-{len(id_sequence)-1}): ")
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            print("No input received.")
        else:
            line = line.strip()
            try:
                idx = int(line)
                value = get_id_at_index(idx)
                print(f"Value at index {idx} is: {value}")
            except ValueError:
                print("Invalid input: not a valid integer.")
            except IndexError:
                print(f"Invalid index: must be between 0 and {len(id_sequence)-1}.")
    except Exception:
        print("An unexpected error occurred.")

    # Five test cases
    print("Running 5 test cases:")
    for test_idx in [0, 3, 9, -1, 100]:
        try:
            print(f"Index {test_idx} -> {get_id_at_index(test_idx)}")
        except Exception as e:
            print(f"Index {test_idx} -> error: {e}")

if __name__ == "__main__":
    main()