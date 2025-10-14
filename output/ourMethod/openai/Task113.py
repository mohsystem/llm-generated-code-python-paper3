from typing import List

MAX_PARTS = 1000
MAX_PART_LEN = 100_000
MAX_TOTAL_LEN = 1_000_000


def safe_concat(parts: List[str], max_total_len: int = MAX_TOTAL_LEN, max_part_len: int = MAX_PART_LEN) -> str:
    if not isinstance(parts, list):
        raise ValueError("Input must be a list of strings.")
    if len(parts) > MAX_PARTS:
        raise ValueError("Too many parts.")
    total = 0
    for s in parts:
        if not isinstance(s, str):
            raise ValueError("All elements must be strings.")
        l = len(s)
        if l > max_part_len:
            raise ValueError("A part exceeded maximum allowed length.")
        total += l
        if total > max_total_len:
            raise ValueError("Total length exceeded maximum allowed length.")
    return "".join(parts)


def run_tests() -> None:
    print(safe_concat(["Hello", " ", "World"]))
    print(safe_concat(["", "abc", "", "def"]))
    print(safe_concat(["multi", "-", "part", "-", "concat"]))
    print(safe_concat([]))
    print(safe_concat(["Safe ", "concat ", "テスト"]))


def read_from_user() -> None:
    try:
        print(f"Enter number of strings to concatenate (0..{MAX_PARTS}):")
        line = input()
        if not line:
            return
        line = line.strip()
        n = int(line)
        if n < 0 or n > MAX_PARTS:
            print("ERROR: Count out of allowed range.")
            return
        parts: List[str] = []
        total = 0
        for _ in range(n):
            s = input()
            if len(s) > MAX_PART_LEN:
                print("ERROR: A part exceeded maximum allowed length.")
                return
            total += len(s)
            if total > MAX_TOTAL_LEN:
                print("ERROR: Total length exceeded maximum allowed length.")
                return
            parts.append(s)
        result = safe_concat(parts)
        print("Concatenated result:")
        print(result)
    except EOFError:
        # No input provided; exit silently.
        pass
    except ValueError:
        print("ERROR: Invalid input.")


def main() -> None:
    run_tests()
    read_from_user()


if __name__ == "__main__":
    main()