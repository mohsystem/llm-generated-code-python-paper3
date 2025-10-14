class Task143:
    @staticmethod
    def sort_array(arr):
        return sorted(arr)

if __name__ == "__main__":
    tests = [
        [3, 1, 2],
        [5, -1, 4, 4, 2],
        [],
        [10],
        [9, 8, 7, 6, 5, 4, 3, 2, 1],
    ]
    for t in tests:
        print(Task143.sort_array(t))