from typing import Optional

def to_jaden_case(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    if s == "":
        return ""
    res_chars: list[str] = []
    capitalize = True
    for ch in s:
        if ch.isalpha():
            if capitalize:
                res_chars.append(ch.upper())
                capitalize = False
            else:
                res_chars.append(ch.lower())
        else:
            res_chars.append(ch)
            if ch == ' ':
                capitalize = True
    return "".join(res_chars)

def main() -> None:
    tests = [
        "How can mirrors be real if our eyes aren't real",
        "",
        "  leading and trailing  ",
        "don't stop-believin' tEST-inG",
        "\"quoted\" words and  multiple   spaces 123abc test",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {t!r} -> {to_jaden_case(t)!r}")

if __name__ == "__main__":
    main()