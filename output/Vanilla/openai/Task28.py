def likes(names):
    n = len(names)
    if n == 0:
        return "no one likes this"
    if n == 1:
        return f"{names[0]} likes this"
    if n == 2:
        return f"{names[0]} and {names[1]} like this"
    if n == 3:
        return f"{names[0]}, {names[1]} and {names[2]} like this"
    return f"{names[0]}, {names[1]} and {n - 2} others like this"


if __name__ == "__main__":
    print(likes([]))
    print(likes(["Peter"]))
    print(likes(["Jacob", "Alex"]))
    print(likes(["Max", "John", "Mark"]))
    print(likes(["Alex", "Jacob", "Mark", "Max", "Lily"]))