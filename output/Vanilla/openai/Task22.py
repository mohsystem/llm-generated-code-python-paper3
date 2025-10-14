def filter_list(items):
    return [x for x in items if isinstance(x, int)]

if __name__ == "__main__":
    print(filter_list([1, 2, "a", "b"]))                       # [1, 2]
    print(filter_list([1, "a", "b", 0, 15]))                   # [1, 0, 15]
    print(filter_list([1, 2, "a", "b", "aasf", "1", "123", 123]))  # [1, 2, 123]
    print(filter_list(["x", "y", "z"]))                        # []
    print(filter_list([0, 99, 1000, "1000", "", 5]))           # [0, 99, 1000, 5]