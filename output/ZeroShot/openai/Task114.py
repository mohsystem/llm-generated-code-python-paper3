class Task114:
    @staticmethod
    def copy_string(s: str):
        if s is None:
            return None
        return s[:]  # create a copy

    @staticmethod
    def concat_strings(a: str, b: str):
        if a is None or b is None:
            return None
        # Python handles large strings but we guard absurd sizes
        total_len = len(a) + len(b)
        if total_len > 1_000_000_000:  # arbitrary safety bound
            raise ValueError("Resulting string too large")
        return a + b

    @staticmethod
    def reverse_string(s: str):
        if s is None:
            return None
        return s[::-1]

    @staticmethod
    def to_uppercase_safe(s: str):
        if s is None:
            return None
        return s.upper()

    @staticmethod
    def replace_substring_safe(s: str, target: str, replacement: str):
        if s is None or target is None or replacement is None:
            return None
        if target == "":
            # Avoid ambiguous behavior; return a copy
            return s[:]
        return s.replace(target, replacement)


if __name__ == "__main__":
    # 5 test cases
    t1 = Task114.copy_string("Hello, World!")
    print("Copy:", t1)

    t2 = Task114.concat_strings("Hello ", "World")
    print("Concat:", t2)

    t3 = Task114.reverse_string("abcdefg")
    print("Reverse:", t3)

    t4 = Task114.to_uppercase_safe("SecuRe123!")
    print("Upper:", t4)

    t5 = Task114.replace_substring_safe("the cat sat on the mat", "at", "oodle")
    print("Replace:", t5)