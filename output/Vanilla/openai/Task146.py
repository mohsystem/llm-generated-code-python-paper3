class Task146:
    @staticmethod
    def find_missing_number(arr):
        n = len(arr) + 1
        xr = 0
        for i in range(1, n + 1):
            xr ^= i
        for v in arr:
            xr ^= v
        return xr

if __name__ == "__main__":
    tests = [
        [2, 3, 1, 5],
        [1],
        [2],
        [1, 2, 3, 4, 5, 6, 7, 8, 10],
        []
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} missing number: {Task146.find_missing_number(t)}")