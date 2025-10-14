import random
import string

class Task128:
    @staticmethod
    def generate_random_int_list(count, min_inclusive, max_inclusive, seed=None):
        if count < 0:
            raise ValueError("count must be >= 0")
        if min_inclusive > max_inclusive:
            raise ValueError("min_inclusive cannot be greater than max_inclusive")
        rng = random.Random(seed) if seed is not None else random.SystemRandom()
        return [rng.randrange(min_inclusive, max_inclusive + 1) for _ in range(count)]

    @staticmethod
    def generate_token(length, allowed_chars=None, seed=None):
        if length < 0:
            raise ValueError("length must be >= 0")
        chars = allowed_chars if (allowed_chars is not None and len(allowed_chars) > 0) else (string.ascii_letters + string.digits)
        rng = random.Random(seed) if seed is not None else random.SystemRandom()
        return ''.join(rng.choice(chars) for _ in range(length))

if __name__ == "__main__":
    print("Python Test Case 1:")
    print(Task128.generate_random_int_list(10, 1, 100, 12345))
    print(Task128.generate_token(16, None, 12345))

    print("Python Test Case 2:")
    print(Task128.generate_random_int_list(5, 0, 9, None))
    print(Task128.generate_token(8, None, None))

    print("Python Test Case 3:")
    print(Task128.generate_random_int_list(7, -50, 50, 999))
    print(Task128.generate_token(12, "ABCDEF0123", 42))

    print("Python Test Case 4:")
    print(Task128.generate_random_int_list(3, 1000, 2000, 55555))
    print(Task128.generate_token(24, "abcdef", 55555))

    print("Python Test Case 5:")
    print(Task128.generate_random_int_list(0, 0, 10, 2021))
    print("[" + Task128.generate_token(0, None, 2021) + "]")