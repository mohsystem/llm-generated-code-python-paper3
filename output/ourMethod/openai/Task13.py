from typing import List

def is_valid_walk(walk: List[str]) -> bool:
    if not isinstance(walk, list) or len(walk) != 10:
        return False
    x = 0
    y = 0
    for s in walk:
        if not isinstance(s, str) or len(s) != 1:
            return False
        c = s
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

def main() -> None:
    tests: List[List[str]] = [
        ['n','s','n','s','n','s','n','s','n','s'],  # True
        ['w'],                                      # False (not 10)
        ['n','n','n','s','n','s','n','s','n','s'],  # False (not back)
        ['e','w','e','w','e','w','e','w','e','w'],  # True
        ['n','s','x','s','n','s','n','s','n','s']   # False (invalid)
    ]
    for idx, t in enumerate(tests, 1):
        print(f"Test {idx}: {is_valid_walk(t)} | Input={t}")

if __name__ == "__main__":
    main()