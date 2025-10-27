def get_value_at_index(index):
    arr = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    return arr[index]

def main():
    tests = [0, 1, 5, 8, 9]
    for idx in tests:
        try:
            result = get_value_at_index(idx)
            print(f"Index {idx} -> {result}")
        except IndexError:
            print(f"Index {idx} -> Index out of bounds")

if __name__ == "__main__":
    main()