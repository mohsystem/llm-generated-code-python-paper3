class Task58:
    @staticmethod
    def XO(s: str) -> bool:
        if s is None:
            return True
        x = 0
        o = 0
        for ch in s:
            if ch == 'x' or ch == 'X':
                x += 1
            elif ch == 'o' or ch == 'O':
                o += 1
        return x == o

if __name__ == "__main__":
    tests = ["ooxx", "xooxx", "ooxXm", "zpzpzpp", "zzoo"]
    for t in tests:
        print(str(Task58.XO(t)).lower())