from typing import List, Tuple

MAX_INPUT_LENGTH = 1000

def is_length_safe(s: str) -> bool:
    return 0 < len(s) <= MAX_INPUT_LENGTH

def is_ascii(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False

def is_valid_ipv4(s: str) -> bool:
    if s is None or not is_length_safe(s) or not is_ascii(s) or (" " in s or "\t" in s):
        return False
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if len(p) == 0 or len(p) > 3:
            return False
        if not p.isdigit():
            return False
        if len(p) > 1 and p[0] == "0":
            return False
        try:
            v = int(p)
        except ValueError:
            return False
        if v < 0 or v > 255:
            return False
    return True

def normalize_ipv4(s: str) -> str:
    if not is_valid_ipv4(s):
        return ""
    parts = s.split(".")
    return ".".join(str(int(p)) for p in parts)

def parse_ipv6_side(side: str) -> List[int] or None:
    res: List[int] = []
    if side == "":
        return res
    tokens = side.split(":")
    for t in tokens:
        if len(t) == 0 or len(t) > 4:
            return None
        try:
            v = int(t, 16)
        except ValueError:
            return None
        if v < 0 or v > 0xFFFF:
            return None
        res.append(v)
        if len(res) > 8:
            return None
    return res

def parse_ipv6_to_groups(s: str) -> List[int] or None:
    if s is None or not is_length_safe(s) or not is_ascii(s) or len(s) == 0:
        return None
    for c in s:
        if not (c == ":" or c.isdigit() or ("a" <= c.lower() <= "f")):
            return None
    dc_first = s.find("::")
    if dc_first != -1 and s.find("::", dc_first + 2) != -1:
        return None
    groups: List[int] = []
    if dc_first != -1:
        left = s[:dc_first]
        right = s[dc_first + 2:]
        left_groups = parse_ipv6_side(left)
        if left_groups is None:
            return None
        right_groups = parse_ipv6_side(right)
        if right_groups is None:
            return None
        total = len(left_groups) + len(right_groups)
        if total >= 8:
            return None
        groups.extend(left_groups)
        groups.extend([0] * (8 - total))
        groups.extend(right_groups)
    else:
        all_groups = parse_ipv6_side(s)
        if all_groups is None or len(all_groups) != 8:
            return None
        groups = all_groups
    if len(groups) != 8:
        return None
    return groups

def is_valid_ipv6(s: str) -> bool:
    return parse_ipv6_to_groups(s) is not None

def normalize_ipv6(s: str) -> str:
    groups = parse_ipv6_to_groups(s)
    if groups is None:
        return ""
    return ":".join(f"{g:04x}" for g in groups)

def detect_ip_type(s: str) -> str:
    if s is None or not is_length_safe(s) or not is_ascii(s):
        return "Invalid"
    if is_valid_ipv4(s):
        return "IPv4"
    if is_valid_ipv6(s):
        return "IPv6"
    return "Invalid"

def process_ip(s: str) -> str:
    t = detect_ip_type(s)
    if t == "IPv4":
        return f"Type: IPv4, Normalized: {normalize_ipv4(s)}"
    if t == "IPv6":
        return f"Type: IPv6, Normalized: {normalize_ipv6(s)}"
    return "Invalid"

def main() -> None:
    tests = [
        "192.168.1.1",
        "255.255.255.255",
        "01.2.3.4",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::8a2e:370:7334",
    ]
    for t in tests:
        print(f"{t} => {process_ip(t)}")

if __name__ == "__main__":
    main()