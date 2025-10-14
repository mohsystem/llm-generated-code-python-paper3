class Task198:
    seed = 123456789

    @classmethod
    def reset_seed(cls, s: int):
        cls.seed = s

    @classmethod
    def next_rand(cls) -> int:
        cls.seed = (cls.seed * 1103515245 + 12345) & 0x7fffffff
        return cls.seed

    @classmethod
    def rand7(cls) -> int:
        return (cls.next_rand() % 7) + 1

    @classmethod
    def rand10(cls) -> int:
        while True:
            a = cls.rand7()
            b = cls.rand7()
            num = (a - 1) * 7 + b  # 1..49
            if num <= 40:
                return ((num - 1) % 10) + 1

    @classmethod
    def generate(cls, n: int):
        return [cls.rand10() for _ in range(n)]

def print_array(arr):
    print("[" + ",".join(str(x) for x in arr) + "]")

def main():
    tests = [1, 2, 3, 10, 20]
    for n in tests:
        Task198.reset_seed(123456789)
        res = Task198.generate(n)
        print_array(res)

if __name__ == "__main__":
    main()