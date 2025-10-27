def process_args(args):
    if args is None or len(args) != 1:
        return None
    if not isinstance(args[0], str):
        return None

    s = args[0]

    end = len(s) - 1
    for i in range(end, -1, -1):
        if s[i] in (' ', '\t'):
            end = i - 1
        else:
            break
    s = s[:end + 1]

    end = len(s) - 1
    for i in range(end, -1, -1):
        if s[i] in ('\n', '\r'):
            end = i - 1
        else:
            break
    s = s[:end + 1]

    s = s + '\0'
    return s


if __name__ == "__main__":
    tests = [
        ["Hello World   \t  \n\n"],
        ["NoTrim"],
        ["a", "b"],
        [5],
        ["abc \t \r\n\r\n"]
    ]

    for idx in range(5):
        t = tests[idx]
        # Ensure exactly one argument is passed to the function
        if idx == 2:
            inp = t  # will fail length check
        else:
            inp = [t[0]]
        res = process_args(inp)
        print(f"Test {idx+1}: {None if res is None else 'len=' + str(len(res)) + ', value=' + repr(res)}")