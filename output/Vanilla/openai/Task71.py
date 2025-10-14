import sys

def convert_to_int(s):
    try:
        return int(s.strip())
    except Exception:
        return None

if __name__ == "__main__":
    args = sys.argv[1:]
    if args:
        for a in args:
            r = convert_to_int(a)
            if r is not None:
                print(f'Input: "{a}" -> {r}')
            else:
                print(f'Input: "{a}" -> invalid')
    else:
        tests = ["123", "  42 ", "-7", "abc", "2147483648"]
        for t in tests:
            r = convert_to_int(t)
            if r is not None:
                print(f'Input: "{t}" -> {r}')
            else:
                print(f'Input: "{t}" -> invalid')