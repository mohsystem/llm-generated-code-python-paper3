import sys

def rtrim(s: str) -> str:
    if s is None:
        return ""
    return s.rstrip()

# Function that accepts input as parameters and returns the output (and exit code)
def process_args(args):
    lines = []
    if args is None or len(args) != 1:
        lines.append("Error: expected exactly one argument.")
        return lines, 1
    input_val = args[0] if args[0] is not None else ""
    lines.append(input_val)
    trimmed = rtrim(input_val)
    lines.append(trimmed)
    return lines, 0

if __name__ == "__main__":
    real_args = sys.argv[1:]
    if len(real_args) > 0:
        lines, code = process_args(real_args)
        for line in lines:
            print(line)
        sys.exit(code)
    else:
        tests = [
            [],                 # 1) zero args -> error
            ["hello"],          # 2) single arg, no trailing ws
            ["abc   "],         # 3) trailing spaces
            ["foo \t"],         # 4) trailing tab
            ["one", "two"]      # 5) multiple args -> error
        ]
        for i, t in enumerate(tests, 1):
            print(f"=== Test {i} ===")
            lines, code = process_args(t)
            for line in lines:
                print(line)
            print(f"Exit code: {code}")