def is_valid_walk(walk):
    if walk is None or len(walk) != 10:
        return False
    x = y = 0
    for d in walk:
        if not isinstance(d, str) or len(d) != 1:
            return False
        if d == 'n':
            y += 1
        elif d == 's':
            y -= 1
        elif d == 'e':
            x += 1
        elif d == 'w':
            x -= 1
        else:
            return False
    return x == 0 and y == 0

if __name__ == "__main__":
    tests = [
        ["n","s","n","s","n","s","n","s","n","s"],
        ["w","e","w","e","w","e","w","e","w","e","w","e"],
        ["w","w","w","w","w","w","w","w","w","w"],
        ["n","s","n","s","n","s","n","s","n","x"],
        ["n","n","e","e","s","s","w","w","n","s"],
    ]
    expected = [True, False, False, False, True]
    for i, t in enumerate(tests):
        print(f"Test {i+1}: {is_valid_walk(t)} (expected {expected[i]})")