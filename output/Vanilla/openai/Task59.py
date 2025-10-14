def accum(s: str) -> str:
    return "-".join(s[i].upper() + s[i].lower() * i for i in range(len(s)))

if __name__ == "__main__":
    tests = [
        "abcd",
        "RqaEzty",
        "cwAt",
        "ZpglnRxqenU",
        "NyffsGeyylB"
    ]
    for t in tests:
        print(accum(t))