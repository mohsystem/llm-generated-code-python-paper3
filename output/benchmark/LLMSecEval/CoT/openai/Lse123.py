class Lse123:
    @staticmethod
    def process(args):
        # First if: ensure exactly one argument
        if not isinstance(args, (list, tuple)) or len(args) != 1:
            return None
        s = args[0]
        # Check the argument is a string
        if not isinstance(s, str):
            return None

        # For loop trims trailing whitespace (spaces and tabs)
        end = len(s) - 1
        for i in range(len(s) - 1, -1, -1):
            if s[i] in (' ', '\t'):
                end = i - 1
            else:
                break
        trimmed = s[:end + 1]

        # Second for loop trims the newlines (removes all '\n' and '\r')
        out_chars = []
        for ch in trimmed:
            if ch not in ('\n', '\r'):
                out_chars.append(ch)
        result = ''.join(out_chars)

        # Python strings are immutable and do not require manual null-termination
        return result

def main():
    tests = [
        ["Hello World   "],
        ["Line with newline\n\n"],
        [" Mix \t \nLine\r\nBreaks\t\t"],
        [],                 # invalid: 0 args
        ["A", "B"]          # invalid: >1 args
    ]
    for i, t in enumerate(tests, 1):
        res = Lse123.process(t)
        print(f"Test {i}: {'null' if res is None else repr(res)}")

if __name__ == "__main__":
    main()