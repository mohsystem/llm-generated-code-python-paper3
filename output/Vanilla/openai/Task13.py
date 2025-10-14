def is_valid_walk(walk):
    if walk is None or len(walk) != 10:
        return False
    x = y = 0
    for c in walk:
        if c == 'n':
            y += 1
        elif c == 's':
            y -= 1
        elif c == 'e':
            x += 1
        elif c == 'w':
            x -= 1
        else:
            return False
    return x == 0 and y == 0

if __name__ == "__main__":
    w1 = ['n','s','n','s','e','w','e','w','n','s']  # true
    w2 = ['n','s','e']  # false (length != 10)
    w3 = ['n','n','n','n','n','s','s','s','e','w']  # false
    w4 = ['e','w','e','w','n','s','n','s','n','s']  # true
    w5 = ['n','n','n','n','n','n','n','n','n','n']  # false

    print(is_valid_walk(w1))
    print(is_valid_walk(w2))
    print(is_valid_walk(w3))
    print(is_valid_walk(w4))
    print(is_valid_walk(w5))