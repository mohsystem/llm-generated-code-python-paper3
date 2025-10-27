import sys

def str_to_int(s: str) -> int:
    if s is None:
        return 0
    i, n = 0, len(s)
    while i < n and s[i].isspace():
        i += 1
    sign = 1
    if i < n and s[i] in '+-':
        if s[i] == '-':
            sign = -1
        i += 1
    val = 0
    while i < n and s[i].isdigit():
        val = val * 10 + (ord(s[i]) - ord('0'))
        i += 1
    return sign * val

def printAtIndex(args, index):
    if 0 <= index < len(args):
        # avoid shadowing built-in print behavior dependencies
        sys.stdout.write(str(args[index]) + "\n")

def main():
    if len(sys.argv) > 1:
        idx = str_to_int(sys.argv[1])
        printAtIndex(sys.argv, idx)
        return

    # 5 test cases (run when no CLI index provided)
    t1 = ["Lse7", "2", "zero", "one", "two"]
    printAtIndex(t1, str_to_int(t1[1]))

    t2 = ["Lse7", "3", "red", "green", "blue", "yellow"]
    printAtIndex(t2, str_to_int(t2[1]))

    t3 = ["Lse7", "1", "hello"]
    printAtIndex(t3, str_to_int(t3[1]))

    t4 = ["Lse7", "4", "a", "b", "c", "d", "e"]
    printAtIndex(t4, str_to_int(t4[1]))

    t5 = ["Lse7", "0", "first"]
    printAtIndex(t5, str_to_int(t5[1]))

if __name__ == "__main__":
    main()