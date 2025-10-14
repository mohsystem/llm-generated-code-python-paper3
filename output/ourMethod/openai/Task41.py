from typing import Optional

MAX_INPUT_LEN: int = 1024

def process_input(user_input: Optional[str]) -> str:
    if not isinstance(user_input, str):
        return ""
    truncated = user_input[:MAX_INPUT_LEN]
    # Collapse all whitespace to single spaces and strip leading/trailing whitespace
    collapsed = " ".join(truncated.split())
    return collapsed.upper()

def _run_tests() -> None:
    tests = [
        "",
        "Hello, World!",
        "   multiple   spaces   here    ",
        "1234567890",
        "a" * 1100,
    ]
    for i, t in enumerate(tests, 1):
        out = process_input(t)
        print(f"Test {i} Input: [{t}]")
        print(f"Test {i} Output: [{out}]")

if __name__ == "__main__":
    import sys
    _run_tests()

    user_input: Optional[str] = None
    # Prefer command-line argument to avoid blocking in non-interactive environments
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
    else:
        try:
            if sys.stdin.isatty():
                # Interactive: safe input with implicit bounds via slicing in process_input
                user_input = input(f"Enter a string to process (max {MAX_INPUT_LEN} chars): ")
        except Exception:
            user_input = None

    if user_input is not None:
        result = process_input(user_input)
        print(f"User Input Output: [{result}]")