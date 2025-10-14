def XO(s: str) -> bool:
    x = o = 0
    for ch in s.lower():
        if ch == 'x':
            x += 1
        elif ch == 'o':
            o += 1
    return x == o

if __name__ == "__main__":
    tests = ["ooxx", "xooxx", "ooxXm", "zpzpzpp", "zzoo"]
    for t in tests:
        print(f'XO("{t}") => {str(XO(t)).lower()}')