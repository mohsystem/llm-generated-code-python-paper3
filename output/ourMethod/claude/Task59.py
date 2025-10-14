
def accum(s: str) -> str:
    if s is None:
        raise ValueError("Input cannot be None")
    
    if not isinstance(s, str):
        raise TypeError("Input must be a string")
    
    if len(s) > 10000:
        raise ValueError("Input string too long")
    
    for c in s:
        if not (('a' <= c <= 'z') or ('A' <= c <= 'Z')):
            raise ValueError("Input must contain only letters a-z and A-Z")
    
    parts = []
    for i, c in enumerate(s):
        upper = c.upper()
        lower = c.lower()
        part = upper + (lower * i)
        parts.append(part)
    
    return "-".join(parts)


if __name__ == "__main__":
    print(accum("abcd"))
    print(accum("RqaEzty"))
    print(accum("cwAt"))
    print(accum("ZpglnRxqenU"))
    print(accum("NyffsGeyylB"))
