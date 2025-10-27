def get_element(arr, index):
    return arr[index]

if __name__ == "__main__":
    import sys
    arr = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]

    if len(sys.argv) > 1:
        try:
            idx = int(sys.argv[1])
            if 0 <= idx < len(arr):
                print(get_element(arr, idx))
            else:
                print("Index out of bounds")
        except ValueError:
            print("Invalid integer argument")
    else:
        tests = [0, 1, 4, 7, 9]
        for idx in tests:
            print(get_element(arr, idx))