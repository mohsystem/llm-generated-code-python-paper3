class Task10:
    @staticmethod
    def get_sum(a, b):
        lo, hi = (a, b) if a <= b else (b, a)
        n = hi - lo + 1
        s = lo + hi
        if n % 2 == 0:
            return (n // 2) * s
        else:
            return n * (s // 2)

if __name__ == "__main__":
    tests = [
        (1, 0),
        (1, 2),
        (0, 1),
        (1, 1),
        (-1, 2)
    ]
    for a, b in tests:
        print(Task10.get_sum(a, b))