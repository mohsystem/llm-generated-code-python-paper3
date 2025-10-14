def accum(s: str) -> str:
    if s is None:
        return ""
    parts = []
    for i, ch in enumerate(s):
        parts.append(ch.upper() + ch.lower() * i)
    return "-".join(parts)

if __name__ == "__main__":
    tests = ["abcd", "RqaEzty", "cwAt", "", "Z"]
    for t in tests:
        print(accum(t))