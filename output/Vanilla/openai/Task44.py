import sys

def _is_safe_ascii(s: str) -> bool:
    for ch in s:
        if ord(ch) > 0x7F:
            return False
        if not (ch.isalnum() or ch in " _-"):
            return False
    return True

def process_data(repeat_count: int, text: str) -> str:
    if not isinstance(repeat_count, int) or repeat_count < 1 or repeat_count > 20:
        return "ERROR: repeatCount out of range [1,20]"
    if text is None:
        return "ERROR: text is null"
    trimmed = text.strip()
    if len(trimmed) < 1 or len(trimmed) > 100:
        return "ERROR: text length must be 1..100 after trimming"
    if not _is_safe_ascii(trimmed):
        return "ERROR: text contains disallowed characters (allowed: A-Z, a-z, 0-9, space, underscore, hyphen)"
    normalized = trimmed.upper()
    checksum = sum((ord(c) & 0xFF) for c in normalized) % 1000
    repeated = "-".join([normalized] * repeat_count)
    result = (
        '{"original":"' + trimmed +
        '", "normalized":"' + normalized +
        '", "repeatCount":' + str(repeat_count) +
        ', "repeated":"' + repeated +
        '", "length":' + str(len(normalized)) +
        ', "checksum":' + str(checksum) + "}"
    )
    return result

if __name__ == "__main__":
    # 5 test cases
    print(process_data(3, "hello world"))
    print(process_data(1, "Safe_Input-123"))
    print(process_data(5, "   trim  me   "))
    print(process_data(0, "abc"))          # invalid repeatCount
    print(process_data(2, "bad!char"))     # invalid character '!'

    # Optional user input via command-line args: first arg is repeatCount, the rest form the text
    if len(sys.argv) >= 3:
        try:
            rc = int(sys.argv[1])
            text = " ".join(sys.argv[2:])
            print(process_data(rc, text))
        except ValueError:
            print("ERROR: first argument must be an integer repeatCount")