# Chain-of-Through process:
# 1) Problem understanding: Read console input, attempt int conversion; also provide a function taking a parameter.
# 2) Security requirements: Validate length, characters, range; avoid exceptions leaking; handle EOF.
# 3) Secure coding generation: Implement robust try_parse_int with strict checks.
# 4) Code review: Ensure handling of empty/null-like values, bounds checks, and safe printing.
# 5) Secure code output: Produce final code with console read and 5 test cases.

from typing import Dict, Optional, Any, Tuple

INT_MIN = -2**31
INT_MAX = 2**31 - 1
MAX_INPUT_LEN = 1000

# Function that accepts input as parameter and returns output
def try_parse_int(s: Optional[str]) -> Dict[str, Any]:
    if s is None:
        return {"success": False, "value": None, "error": "Input is None"}

    s = s.strip()

    if len(s) == 0:
        return {"success": False, "value": None, "error": "Empty input"}

    if len(s) > MAX_INPUT_LEN:
        return {"success": False, "value": None, "error": "Input too long"}

    # Validate optional sign and digits
    if s[0] in "+-":
        if len(s) == 1:
            return {"success": False, "value": None, "error": "Invalid characters"}
        if not s[1:].isdigit():
            return {"success": False, "value": None, "error": "Invalid characters"}
    else:
        if not s.isdigit():
            return {"success": False, "value": None, "error": "Invalid characters"}

    # Convert and check range
    try:
        val = int(s, 10)
    except Exception:
        return {"success": False, "value": None, "error": "Conversion error"}

    if val < INT_MIN or val > INT_MAX:
        return {"success": False, "value": None, "error": "Number out of int range"}

    return {"success": True, "value": val, "error": None}


def main():
    try:
        line = input("Enter a value to convert to integer:\n")
    except EOFError:
        print("No input received.")
    else:
        res = try_parse_int(line)
        if res["success"]:
            print(f"Success: {res['value']}")
        else:
            print(f"Error: {res['error']}")

    # 5 test cases
    tests = ["123", "  -42  ", "2147483647", "2147483648", "abc"]
    print("---- Test Cases ----")
    for t in tests:
        r = try_parse_int(t)
        print(f'Input: "{t}" -> {"Success: " + str(r["value"]) if r["success"] else "Error: " + str(r["error"])}')


if __name__ == "__main__":
    main()