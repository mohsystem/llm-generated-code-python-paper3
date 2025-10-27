import sys

def trim_trailing(s: str) -> str:
    return s.rstrip()

# Function: accepts input as parameter and returns outputs
def process_input(input_str: str):
    return (input_str, trim_trailing(input_str))

# Command-line behavior as described
def run_with_args(argv):
    if len(argv) != 1:
        print("Error: exactly one argument required.", file=sys.stderr)
        sys.exit(1)
    input_str = argv[0]
    print(input_str)
    trimmed = input_str.rstrip()
    print(trimmed)
    sys.exit(0)

if __name__ == "__main__":
    # 5 test cases
    tests = [
        "hello world   ",
        "   leading and trailing\t\t",
        "no-trailing",
        "tabs-and-newline\t\t\n",
        ""
    ]
    for i, t in enumerate(tests, 1):
        orig, trimmed = process_input(t)
        print(f"TEST{i} original: [{orig}]")
        print(f"TEST{i} trimmed: [{trimmed}]")
    # If any CLI args are provided, run the specified behavior
    if len(sys.argv) > 1:
        run_with_args(sys.argv[1:])