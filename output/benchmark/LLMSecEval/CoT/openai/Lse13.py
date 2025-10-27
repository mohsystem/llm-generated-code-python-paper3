import sys
import select

ID_SEQUENCE = [101, 205, 309, 412, 518, 623, 734, 845, 956, 1067]

def get_value_at_index(index: int) -> int:
    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")
    if index < 0 or index >= len(ID_SEQUENCE):
        raise IndexError("Index out of range.")
    return ID_SEQUENCE[index]

def main():
    print("Enter an index to retrieve from id_sequence:")
    input_checked = False
    try:
        rlist, _, _ = select.select([sys.stdin], [], [], 0)
        if rlist:
            line = sys.stdin.readline()
            if line:
                try:
                    idx = int(line.strip())
                    try:
                        val = get_value_at_index(idx)
                        print(f"Value at index {idx} is: {val}")
                    except Exception as e:
                        print(f"Error: {e}")
                except ValueError:
                    print("No valid integer input provided.")
            input_checked = True
    except Exception:
        pass
    if not input_checked:
        print("No input detected. Skipping user query.")

    tests = [0, 3, 9, -1, 100]
    print("Running 5 test cases:")
    for t in tests:
        try:
            val = get_value_at_index(t)
            print(f"Index {t} => {val}")
        except Exception as e:
            print(f"Index {t} => Error: {e}")

if __name__ == "__main__":
    main()