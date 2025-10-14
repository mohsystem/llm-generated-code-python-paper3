
def accum(s):
    result = []
    for i, c in enumerate(s):
        result.append(c.upper() + c.lower() * i)
    return "-".join(result)

if __name__ == "__main__":
    print(accum("abcd"))
    print(accum("RqaEzty"))
    print(accum("cwAt"))
    print(accum("ZpglnRxqenU"))
    print(accum("NyffsGeyylB"))
