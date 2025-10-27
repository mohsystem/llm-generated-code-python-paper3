class Lse17:
    @staticmethod
    def get_value_at_index(arr, index):
        if arr is None:
            raise ValueError("Array is None")
        if index < 0 or index >= len(arr):
            raise IndexError("Invalid index")
        return arr[index]

if __name__ == "__main__":
    arr = [10, 25, 37, 48, 59]
    test_indices = [0, 1, 2, 3, 4]
    for idx in test_indices:
        print(Lse17.get_value_at_index(arr, idx))