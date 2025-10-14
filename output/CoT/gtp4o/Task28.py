def likes(names):
    if names is None or len(names) == 0:
        return "no one likes this"
    def safe(s):
        return "null" if s is None else s
    n = len(names)
    a = safe(names[0])
    if n == 1:
        return f"{a} likes this"
    if n == 2:
        b = safe(names[1])
        return f"{a} and {b} like this"
    if n == 3:
        b = safe(names[1])
        c = safe(names[2])
        return f"{a}, {b} and {c} like this"
    b = safe(names[1])
    return f"{a}, {b} and {n - 2} others like this"


if __name__ == "__main__":
    tests = [
        [],
        ["Peter"],
        ["Jacob", "Alex"],
        ["Max", "John", "Mark"],
        ["Alex", "Jacob", "Mark", "Max"],
    ]
    for t in tests:
        print(f"{t} --> {likes(t)}")