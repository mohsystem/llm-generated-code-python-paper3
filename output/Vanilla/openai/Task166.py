class Task166:
    @staticmethod
    def posNegSort(arr):
        positives = sorted([x for x in arr if x > 0])
        res = []
        i = 0
        for x in arr:
            if x > 0:
                res.append(positives[i])
                i += 1
            else:
                res.append(x)
        return res

if __name__ == "__main__":
    tests = [
        [6, 3, -2, 5, -8, 2, -2],
        [6, 5, 4, -1, 3, 2, -1, 1],
        [-5, -5, -5, -5, 7, -5],
        [],
        [9, -3, 8, -1, -2, 7, 6],
    ]
    for t in tests:
        print(Task166.posNegSort(t))